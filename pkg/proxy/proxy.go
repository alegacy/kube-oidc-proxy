// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	ctx "context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/context"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/hooks"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/logging"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/tokenreview"
)

const (
	UserHeaderClientIPKey = "Remote-Client-IP"
	timestampLayout       = "2006-01-02T15:04:05-0700"
)

var (
	errUnauthorized          = errors.New("Unauthorized")
	errNoName                = errors.New("No name in OIDC info")
	errNoImpersonationConfig = errors.New("No impersonation configuration in context")
)

type Config struct {
	DisableImpersonation bool
	TokenReview          bool

	FlushInterval   time.Duration
	ExternalAddress string

	ExtraUserHeaders                map[string][]string
	ExtraUserHeadersClientIPEnabled bool
}

type errorHandlerFn func(http.ResponseWriter, *http.Request, error)

type Proxy struct {
	oidcRequestAuther     *bearertoken.Authenticator
	tokenAuther           authenticator.Token
	tokenReviewer         *tokenreview.TokenReview
	subjectAccessReviewer *subjectaccessreview.SubjectAccessReview
	secureServingInfo     *server.SecureServingInfo
	auditor               *audit.Audit
	dynamicClientCert     *DynamicCertificate

	restConfig            *rest.Config
	clientTransport       http.RoundTripper
	noAuthClientTransport http.RoundTripper

	config *Config

	hooks       *hooks.Hooks
	handleError errorHandlerFn
}

// implement oidc.CAContentProvider to load
// the ca file from the options
type CAFromFile struct {
	CAFile string
}

func (caFromFile CAFromFile) CurrentCABundleContent() []byte {
	res, _ := ioutil.ReadFile(caFromFile.CAFile)
	return res
}

// DynamicCertificate wraps DynamicCertKeyPairContent so that we can attach a function to it that can be used by
// the TLS client config to load the client certificate dynamically
type DynamicCertificate struct {
	*dynamiccertificates.DynamicCertKeyPairContent
}

// GetClientCertificate returns a client certificate based on the most recent certificate and key data loaded from the
// file system.
func (c *DynamicCertificate) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	certBytes, keyBytes := c.CurrentCertKeyContent()
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load OIDC client certificate: %w", err)
	}
	return &cert, nil
}

// NewDynamicCertificate create a new instance of DynamicCertificate using the supplied certificate and key files
func NewDynamicCertificate(purpose, certFile, keyFile string) (*DynamicCertificate, error) {
	content, err := dynamiccertificates.NewDynamicServingContentFromFiles(purpose, certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create new dynamic serving content for '%s': %w", purpose, err)
	}
	return &DynamicCertificate{content}, nil
}

// setupClient creates an HTTP client using the dynamic content provided for the client certificate and the CA bundle.
// This function is based on how the setup would have been set up by the underlying OIDC code had we not passed in our
// own client.
func setupClient(dynamicClientCert *DynamicCertificate, caFromFile oidc.CAContentProvider) (*http.Client, error) {
	var roots *x509.CertPool
	if caFromFile != nil {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caFromFile.CurrentCABundleContent()) {
			return nil, fmt.Errorf("failed to append OIDC ca bundle to pool")
		}
	} else {
		klog.Info("OIDC: No x509 certificates provided, will use host's root CA set")
	}

	// Copied from http.DefaultTransport.
	tr := net.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, GetClientCertificate: dynamicClientCert.GetClientCertificate},
	})

	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

func New(restConfig *rest.Config,
	oidcOptions *options.OIDCAuthenticationOptions,
	auditOptions *options.AuditOptions,
	tokenReviewer *tokenreview.TokenReview,
	subjectAccessReviewer *subjectaccessreview.SubjectAccessReview,
	ssinfo *server.SecureServingInfo,
	config *Config) (*Proxy, error) {
	var err error

	// load the CA from the file listed in the options
	caFromFile := CAFromFile{
		CAFile: oidcOptions.CAFile,
	}

	// setup static JWT Auhenticator
	jwtConfig := apiserver.JWTAuthenticator{
		Issuer: apiserver.Issuer{
			URL:                  oidcOptions.IssuerURL,
			Audiences:            []string{oidcOptions.ClientID},
			CertificateAuthority: string(caFromFile.CurrentCABundleContent()),
		},

		ClaimMappings: apiserver.ClaimMappings{
			Username: apiserver.PrefixedClaimOrExpression{
				Claim:  oidcOptions.UsernameClaim,
				Prefix: &oidcOptions.UsernamePrefix,
			},
			Groups: apiserver.PrefixedClaimOrExpression{
				Claim:  oidcOptions.GroupsClaim,
				Prefix: &oidcOptions.GroupsPrefix,
			},
		},
	}

	tokenAutherOptions := oidc.Options{
		CAContentProvider: caFromFile,
		//RequiredClaims:       oidcOptions.RequiredClaims,
		SupportedSigningAlgs: oidcOptions.SigningAlgs,
		JWTAuthenticator:     jwtConfig,
	}

	var dyCert *DynamicCertificate
	if oidcOptions.ClientCertKey.CertFile != "" {
		// Use the client certificate and key to enable mTLS
		dyCert, err = NewDynamicCertificate("oidc-client", oidcOptions.ClientCertKey.CertFile, oidcOptions.ClientCertKey.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC client certificate loader: %v", err)
		}

		client, err := setupClient(dyCert, caFromFile)
		if err != nil {
			return nil, err
		}

		tokenAutherOptions.Client = client
		tokenAutherOptions.CAContentProvider = nil
	}

	// generate tokenAuther from oidc config
	tokenAuther, err := oidc.New(ctx.TODO(), tokenAutherOptions)
	if err != nil {
		return nil, err
	}

	auditor, err := audit.New(auditOptions, config.ExternalAddress, ssinfo)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		restConfig:            restConfig,
		hooks:                 hooks.New(),
		tokenReviewer:         tokenReviewer,
		subjectAccessReviewer: subjectAccessReviewer,
		secureServingInfo:     ssinfo,
		config:                config,
		oidcRequestAuther:     bearertoken.New(tokenAuther),
		tokenAuther:           tokenAuther,
		auditor:               auditor,
		dynamicClientCert:     dyCert,
	}, nil
}

func (p *Proxy) Run(stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error) {
	// standard round tripper for proxy to API Server
	clientRT, err := p.roundTripperForRestConfig(p.restConfig)
	if err != nil {
		return nil, nil, err
	}
	p.clientTransport = clientRT

	if p.dynamicClientCert != nil {
		// Start monitoring the OIDC client TLS certificate
		c, cancel := ctx.WithCancel(ctx.Background())
		defer cancel()
		go p.dynamicClientCert.Run(c, 1)
	}

	// No auth round tripper for no impersonation
	if p.config.DisableImpersonation || p.config.TokenReview {
		noAuthClientRT, err := p.roundTripperForRestConfig(&rest.Config{
			APIPath: p.restConfig.APIPath,
			Host:    p.restConfig.Host,
			Timeout: p.restConfig.Timeout,
			TLSClientConfig: rest.TLSClientConfig{
				CAFile: p.restConfig.CAFile,
				CAData: p.restConfig.CAData,
			},
		})
		if err != nil {
			return nil, nil, err
		}

		p.noAuthClientTransport = noAuthClientRT
	}

	// get API server url
	url, err := url.Parse(p.restConfig.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse url: %s", err)
	}

	p.handleError = p.newErrorHandler()

	// Set up proxy handler using proxy
	proxyHandler := httputil.NewSingleHostReverseProxy(url)
	proxyHandler.Transport = p
	proxyHandler.ErrorHandler = p.handleError
	proxyHandler.FlushInterval = p.config.FlushInterval

	waitCh, listenerStoppedCh, err := p.serve(proxyHandler, stopCh)
	if err != nil {
		return nil, nil, err
	}

	return waitCh, listenerStoppedCh, nil
}

func (p *Proxy) serve(handler http.Handler, stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error) {
	// Setup proxy handlers
	handler = p.withHandlers(handler)

	// Run auditor
	if err := p.auditor.Run(stopCh); err != nil {
		return nil, nil, err
	}

	// securely serve using serving config
	waitCh, listenerStoppedCh, err := p.secureServingInfo.Serve(handler, time.Second*60, stopCh)
	if err != nil {
		return nil, nil, err
	}

	return waitCh, listenerStoppedCh, nil
}

// RoundTrip is called last and is used to manipulate the forwarded request using context.
func (p *Proxy) RoundTrip(req *http.Request) (*http.Response, error) {
	// Here we have successfully authenticated so now need to determine whether
	// we need use impersonation or not.

	// If no impersonation then we return here without setting impersonation
	// header but re-introduce the token we removed.
	if context.NoImpersonation(req) {
		token := context.BearerToken(req)
		req.Header.Add("Authorization", token)
		return p.noAuthClientTransport.RoundTrip(req)
	}

	// Get the impersonation headers from the context.
	impersonationConf := context.ImpersonationConfig(req)
	if impersonationConf == nil {
		return nil, errNoImpersonationConfig
	}

	// Set up impersonation request.
	rt := transport.NewImpersonatingRoundTripper(*impersonationConf.ImpersonationConfig, p.clientTransport)

	// Log the request
	logging.LogSuccessfulRequest(req, *impersonationConf.InboundUser, *impersonationConf.ImpersonatedUser)

	// Push request through round trippers to the API server.
	return rt.RoundTrip(req)
}

func (p *Proxy) reviewToken(rw http.ResponseWriter, req *http.Request) bool {
	var remoteAddr string
	req, remoteAddr = context.RemoteAddr(req)

	klog.V(4).Infof("attempting to validate a token in request using TokenReview endpoint(%s)",
		remoteAddr)

	ok, err := p.tokenReviewer.Review(req)
	if err != nil {
		klog.Errorf("unable to authenticate the request via TokenReview due to an error (%s): %s",
			remoteAddr, err)
		return false
	}

	if !ok {
		klog.V(4).Infof("passing request with valid token through (%s)",
			remoteAddr)

		return false
	}

	// No error and ok so passthrough the request
	return true
}

func (p *Proxy) roundTripperForRestConfig(config *rest.Config) (http.RoundTripper, error) {
	// get golang tls config to the API server
	tlsConfig, err := rest.TLSConfigFor(config)
	if err != nil {
		return nil, err
	}

	// create tls transport to request
	tlsTransport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	// get kube transport config form rest client config
	restTransportConfig, err := config.TransportConfig()
	if err != nil {
		return nil, err
	}

	// wrap golang tls config with kube transport round tripper
	clientRT, err := transport.HTTPWrappersForConfig(restTransportConfig, tlsTransport)
	if err != nil {
		return nil, err
	}

	return clientRT, nil
}

// Return the proxy OIDC token authenticator
func (p *Proxy) OIDCTokenAuthenticator() authenticator.Token {
	return p.tokenAuther
}

func (p *Proxy) RunPreShutdownHooks() error {
	return p.hooks.RunPreShutdownHooks()
}
