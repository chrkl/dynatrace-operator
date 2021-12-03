/*
Copyright 2021 Dynatrace LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package updates

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	dynatracev1beta1 "github.com/Dynatrace/dynatrace-operator/api/v1beta1"
	"github.com/Dynatrace/dynatrace-operator/controllers"
	"github.com/Dynatrace/dynatrace-operator/controllers/dtpullsecret"
	"github.com/Dynatrace/dynatrace-operator/controllers/dtversion"
	"github.com/Dynatrace/dynatrace-operator/logger"
	"github.com/Dynatrace/dynatrace-operator/scheme/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	testName      = "test-name"
	testNamespace = "test-namespace"
	testPaaSToken = "test-paas-token"
	testRegistry  = "registry"
	testVersion   = "1.0.0"
	testHash      = "abcdefg1234"
)

func TestReconcile_UpdateImageVersion(t *testing.T) {
	ctx := context.Background()

	dk := dynatracev1beta1.DynaKube{
		ObjectMeta: metav1.ObjectMeta{Name: testName, Namespace: testNamespace},
		Spec: dynatracev1beta1.DynaKubeSpec{
			KubernetesMonitoring: dynatracev1beta1.KubernetesMonitoringSpec{
				Enabled: true,
			},
			OneAgent: dynatracev1beta1.OneAgentSpec{
				ClassicFullStack: &dynatracev1beta1.ClassicFullStackSpec{},
			},
		},
	}

	fakeClient := fake.NewClient()

	now := metav1.Now()
	dkState := &controllers.DynakubeState{Instance: &dk, Log: logger.NewDTLogger(), Now: now}
	status := &dkState.Instance.Status
	versionedComponents := []dynatracev1beta1.NamedVersionStatuser{
		&status.ActiveGate, &status.OneAgent, &status.ExtensionController, &status.StatsD,
	}

	t.Run("no update if version provider returns error", func(t *testing.T) {
		errVerProvider := func(img string, dockerConfig *dtversion.DockerConfig) (dtversion.ImageVersion, error) {
			return dtversion.ImageVersion{}, errors.New("Not implemented")
		}
		upd, err := ReconcileVersions(ctx, dkState, fakeClient, errVerProvider)
		assert.Error(t, err)
		assert.False(t, upd)
	})

	data, err := buildTestDockerAuth(t)
	require.NoError(t, err)

	err = createTestPullSecret(t, fakeClient, dkState, data)
	require.NoError(t, err)

	sampleVerProvider := func(img string, dockerConfig *dtversion.DockerConfig) (dtversion.ImageVersion, error) {
		return dtversion.ImageVersion{Version: testVersion, Hash: testHash}, nil
	}

	t.Run("image versions and hashes were updated", func(t *testing.T) {
		{
			upd, err := ReconcileVersions(ctx, dkState, fakeClient, sampleVerProvider)
			assert.NoError(t, err)
			assert.True(t, upd)
		}
		for _, component := range versionedComponents {
			assertVersionStatusEquals(t, testVersion, testHash, now, component)
		}
		{
			upd, err := ReconcileVersions(ctx, dkState, fakeClient, sampleVerProvider)
			assert.NoError(t, err)
			assert.False(t, upd)
		}
	})
}

func assertVersionStatusEquals(t *testing.T, expectedVersion, expectedHash string, timePoint metav1.Time, verStatuser dynatracev1beta1.NamedVersionStatuser) {
	assert.Equalf(t, expectedVersion, verStatuser.GetVersion(), "Unexpected version for versioned component %s", verStatuser.GetName())
	assert.Equalf(t, expectedHash, verStatuser.GetImageHash(), "Unexpected image hash for versioned component %s", verStatuser.GetName())
	if ts := verStatuser.GetLastUpdateProbeTimestamp(); assert.NotNilf(t, ts, "Unexpectedly missing update timestamp for versioned component %s", verStatuser.GetName()) {
		assert.Equalf(t, timePoint, *ts, "Unexpected update timestamp for versioned component %s", verStatuser.GetName())
	}
}

// Adding *testing.T parameter to prevent usage in production code
func createTestPullSecret(_ *testing.T, clt client.Client, dkState *controllers.DynakubeState, data []byte) error {
	return clt.Create(context.TODO(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: dkState.Instance.Namespace,
			Name:      dkState.Instance.Name + dtpullsecret.PullSecretSuffix,
		},
		Data: map[string][]byte{
			".dockerconfigjson": data,
		},
	})
}

// Adding *testing.T parameter to prevent usage in production code
func buildTestDockerAuth(_ *testing.T) ([]byte, error) {
	dockerConf := struct {
		Auths map[string]dtversion.DockerAuth `json:"auths"`
	}{
		Auths: map[string]dtversion.DockerAuth{
			testRegistry: {
				Username: testName,
				Password: testPaaSToken,
			},
		},
	}
	return json.Marshal(dockerConf)
}
