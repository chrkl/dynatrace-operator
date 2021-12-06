package agproxysecret

import (
	"context"
	"fmt"
	"net/url"

	dynatracev1beta1 "github.com/Dynatrace/dynatrace-operator/src/api/v1beta1"
	agcapability "github.com/Dynatrace/dynatrace-operator/src/controllers/activegate/capability"
	"github.com/Dynatrace/dynatrace-operator/src/kubeobjects"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	proxyHostField     = "host"
	proxyPortField     = "port"
	proxyUsernameField = "username"
	proxyPasswordField = "password"

	proxySecretKey              = "proxy"
	activeGateProxySecretSuffix = "proxy"
)

// ActiveGateProxySecretGenerator manages the ActiveGate proxy secret generation for the user namespaces.
type ActiveGateProxySecretGenerator struct {
	client    client.Client
	apiReader client.Reader
	logger    logr.Logger
	namespace string
}

func NewActiveGateProxySecretGenerator(client client.Client, apiReader client.Reader, ns string, logger logr.Logger) *ActiveGateProxySecretGenerator {
	return &ActiveGateProxySecretGenerator{
		client:    client,
		apiReader: apiReader,
		namespace: ns,
		logger:    logger,
	}
}

func (g *ActiveGateProxySecretGenerator) GenerateForDynakube(ctx context.Context, dk *dynatracev1beta1.DynaKube) (bool, error) {
	data, err := g.prepare(ctx, dk)
	if err != nil {
		return false, err
	}
	return kubeobjects.CreateOrUpdateSecretIfNotExists(g.client, g.apiReader, BuildProxySecretName(dk.Name), g.namespace, data, corev1.SecretTypeOpaque, g.logger)
}

func (g *ActiveGateProxySecretGenerator) EnsureDeleted(ctx context.Context, dk *dynatracev1beta1.DynaKube) error {
	secret := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: BuildProxySecretName(dk.Name), Namespace: dk.Namespace}}
	if err := g.client.Delete(ctx, &secret); err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	return nil
}

func BuildProxySecretName(dkName string) string {
	return dkName + "-" + agcapability.MultiActiveGateName + "-" + activeGateProxySecretSuffix
}

func (g *ActiveGateProxySecretGenerator) prepare(ctx context.Context, dk *dynatracev1beta1.DynaKube) (map[string][]byte, error) {
	var err error
	proxy := ""
	if dk.Spec.Proxy != nil && dk.Spec.Proxy.ValueFrom != "" {
		if proxy, err = g.proxyFromUserSecret(ctx, dk); err != nil {
			return nil, err
		}
	} else if dk.Spec.Proxy != nil && len(dk.Spec.Proxy.Value) > 0 {
		proxy = proxyFromSpec(dk)
	} else {
		// the parsed-proxy secret is expected to exist and the entrypoint.sh script handles empty values properly
		return map[string][]byte{
			proxyHostField:     []byte(""),
			proxyPortField:     []byte(""),
			proxyUsernameField: []byte(""),
			proxyPasswordField: []byte(""),
		}, nil
	}

	host, port, username, password, err := parseProxyUrl(proxy)
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		proxyHostField:     []byte(host),
		proxyPortField:     []byte(port),
		proxyUsernameField: []byte(username),
		proxyPasswordField: []byte(password),
	}, nil
}

func proxyFromSpec(dk *dynatracev1beta1.DynaKube) string {
	return dk.Spec.Proxy.Value
}

func (g *ActiveGateProxySecretGenerator) proxyFromUserSecret(ctx context.Context, dk *dynatracev1beta1.DynaKube) (string, error) {
	var proxySecret corev1.Secret
	if err := g.client.Get(ctx, client.ObjectKey{Name: dk.Spec.Proxy.ValueFrom, Namespace: g.namespace}, &proxySecret); err != nil {
		return "", errors.WithMessage(err, fmt.Sprintf("failed to query %s secret", dk.Spec.Proxy.ValueFrom))
	}

	proxy, ok := proxySecret.Data[proxySecretKey]
	if !ok {
		return "", fmt.Errorf("invalid secret %s", dk.Spec.Proxy.ValueFrom)
	}
	return string(proxy), nil
}

func parseProxyUrl(proxy string) (host string, port string, username string, password string, err error) {
	proxyUrl, err := url.Parse(proxy)
	if err != nil {
		return "", "", "", "", err
	}

	passwd, _ := proxyUrl.User.Password()
	return proxyUrl.Hostname(), proxyUrl.Port(), proxyUrl.User.Username(), passwd, nil
}
