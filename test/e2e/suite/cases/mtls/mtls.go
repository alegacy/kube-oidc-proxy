// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"github.com/jetstack/kube-oidc-proxy/test/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework"
	"github.com/jetstack/kube-oidc-proxy/test/kind"
)

var _ = framework.CasesDescribe("mTLS", func() {
	f := framework.NewDefaultFramework("mtls")

	It("Should become ready if the issuer accepts our client certificate", func() {
		// Create a new cert/key bundle that can be used as a TLS client
		clientBundle, err := util.NewTLSSelfSignedCertKey("proxy-oidc-client", []net.IP{net.ParseIP("127.0.0.1")}, nil)
		Expect(err).NotTo(HaveOccurred())

		// Set up a secret to hold the new certificate/key pair
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "oidc-client",
				Namespace: f.Namespace.Name,
			},
			Data: map[string][]byte{
				"tls.crt": clientBundle.CertBytes,
				"tls.key": clientBundle.KeyBytes,
			},
		}

		By("Creating a secret to hold the OIDC client certificate/key pair")
		_, err = f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).Create(context.TODO(), secret, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Since this is a self-signed certificate pass it to the issuers as our "CA".
		volume := corev1.Volume{
			Name: "oidc-client",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: "oidc-client",
				},
			},
		}

		// Re-deploy the Issuer with the --tls-client-ca-file argument which will force certs to be required and to be
		// validated to the certificate provided in that file.  Since we've self-signed our own then we just pass it
		// here as well.
		f.DeployIssuerWith([]corev1.Volume{volume}, "--tls-client-ca-file=/oidc-client/tls.crt")

		// Re-deploy the Proxy with the same volume so that it can use it to find its OIDC client TLS cert/key.
		f.DeployProxyWith([]corev1.Volume{volume},
			"--oidc-tls-client-cert-file=/oidc-client/tls.crt",
			"--oidc-tls-client-key-file=/oidc-client/tls.key")

		time.Sleep(time.Second * 10)

		err = f.Helper().WaitForDeploymentReady(f.Namespace.Name, kind.ProxyImageName, time.Second*5)
		Expect(err).NotTo(HaveOccurred())
	})
})
