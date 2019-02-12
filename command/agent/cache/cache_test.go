package cache

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/hashicorp/vault/logical"

	"github.com/go-test/deep"
	hclog "github.com/hashicorp/go-hclog"
	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/userpass"
	"github.com/hashicorp/vault/helper/logging"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
)

const policyAdmin = `
path "*" {
	capabilities = ["sudo", "create", "read", "update", "delete", "list"]
}
`

// testSetupClusterAndAgent is a helper func used to set up a test cluster and
// caching agent. It returns a cleanup func that should be deferred immediately
// along with two clients, one for direct cluster communication and another to
// talk to the caching agent.
func setupClusterAndAgent(t *testing.T, coreConfig *vault.CoreConfig) (func(), *api.Client, *api.Client) {
	t.Helper()

	// Handle sane defaults
	if coreConfig == nil {
		coreConfig = &vault.CoreConfig{
			DisableMlock: true,
			DisableCache: true,
			Logger:       hclog.NewNullLogger(),
			CredentialBackends: map[string]logical.Factory{
				"userpass": userpass.Factory,
			},
		}
	}

	if coreConfig.CredentialBackends == nil {
		coreConfig.CredentialBackends = map[string]logical.Factory{
			"userpass": userpass.Factory,
		}
	}

	// Init new test cluster
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)

	// clusterClient is the client that is used to talk directly to the cluster.
	clusterClient := cores[0].Client

	// Add an admin policy
	if err := clusterClient.Sys().PutPolicy("admin", policyAdmin); err != nil {
		t.Fatal(err)
	}

	// Set up the userpass auth backend and an admin user. Used for getting a token
	// for the agent later down in this func.
	clusterClient.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})

	_, err := clusterClient.Logical().Write("auth/userpass/users/foo", map[string]interface{}{
		"password": "bar",
		"policies": []string{"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Set up env vars for agent consumption
	origEnvVaultAddress := os.Getenv(api.EnvVaultAddress)
	os.Setenv(api.EnvVaultAddress, clusterClient.Address())

	origEnvVaultCACert := os.Getenv(api.EnvVaultCACert)
	os.Setenv(api.EnvVaultCACert, fmt.Sprintf("%s/ca_cert.pem", cluster.TempDir))

	cacheLogger := logging.NewVaultLogger(hclog.Trace)
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// Start listening to requests
	err = Run(ctx, &Config{
		Token:            clusterClient.Token(),
		UseAutoAuthToken: false,
		Listeners:        []net.Listener{listener},
		Logger:           cacheLogger.Named("cache"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// testClient is the client that is used to talk to the agent for proxying/caching behavior.
	testClient, err := clusterClient.Clone()
	if err != nil {
		t.Fatal(err)
	}

	if err := testClient.SetAddress("http://" + listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	// Login via userpass method to derive a managed token. Set that token as the
	// testClient's token
	resp, err := testClient.Logical().Write("auth/userpass/login/foo", map[string]interface{}{
		"password": "bar",
	})
	if err != nil {
		t.Fatal(err)
	}
	testClient.SetToken(resp.Auth.ClientToken)

	cleanup := func() {
		cluster.Cleanup()
		os.Setenv(api.EnvVaultAddress, origEnvVaultAddress)
		os.Setenv(api.EnvVaultCACert, origEnvVaultCACert)
		listener.Close()
	}

	return cleanup, clusterClient, testClient
}

func TestCache_NonCacheable(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		LogicalBackends: map[string]logical.Factory{
			"kv": kv.Factory,
		},
	}

	cleanup, _, testClient := setupClusterAndAgent(t, coreConfig)
	defer cleanup()

	// Query mounts first
	origMounts, err := testClient.Sys().ListMounts()
	if err != nil {
		t.Fatal(err)
	}

	// Mount a kv backend
	if err := testClient.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Query mounts again
	newMounts, err := testClient.Sys().ListMounts()
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(origMounts, newMounts); diff == nil {
		t.Logf("response #1: %#v", origMounts)
		t.Logf("response #2: %#v", newMounts)
		t.Fatal("expected requests to be not cached")
	}
}

func TestCache_AuthResponse(t *testing.T) {
	cleanup, _, testClient := setupClusterAndAgent(t, nil)
	defer cleanup()

	resp, err := testClient.Logical().Write("auth/token/create", nil)
	if err != nil {
		t.Fatal(err)
	}
	token := resp.Auth.ClientToken
	testClient.SetToken(token)

	// Test on auth response by creating a child token
	{
		proxiedResp, err := testClient.Logical().Write("auth/token/create", map[string]interface{}{
			"policies": "default",
		})
		if err != nil {
			t.Fatal(err)
		}
		if proxiedResp.Auth == nil || proxiedResp.Auth.ClientToken == "" {
			t.Fatalf("expected a valid client token in the response, got = %#v", proxiedResp)
		}

		cachedResp, err := testClient.Logical().Write("auth/token/create", map[string]interface{}{
			"policies": "default",
		})
		if err != nil {
			t.Fatal(err)
		}
		if cachedResp.Auth == nil || cachedResp.Auth.ClientToken == "" {
			t.Fatalf("expected a valid client token in the response, got = %#v", cachedResp)
		}

		if diff := deep.Equal(proxiedResp.Auth.ClientToken, cachedResp.Auth.ClientToken); diff != nil {
			t.Fatal(diff)
		}
	}

	// Test on *non-renewable* auth response by creating a child root token
	{
		proxiedResp, err := testClient.Logical().Write("auth/token/create", nil)
		if err != nil {
			t.Fatal(err)
		}
		if proxiedResp.Auth == nil || proxiedResp.Auth.ClientToken == "" {
			t.Fatalf("expected a valid client token in the response, got = %#v", proxiedResp)
		}

		cachedResp, err := testClient.Logical().Write("auth/token/create", nil)
		if err != nil {
			t.Fatal(err)
		}
		if cachedResp.Auth == nil || cachedResp.Auth.ClientToken == "" {
			t.Fatalf("expected a valid client token in the response, got = %#v", cachedResp)
		}

		if diff := deep.Equal(proxiedResp.Auth.ClientToken, cachedResp.Auth.ClientToken); diff != nil {
			t.Fatal(diff)
		}
	}
}

func TestCache_LeaseResponse(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		LogicalBackends: map[string]logical.Factory{
			"kv": vault.LeasedPassthroughBackendFactory,
		},
	}

	cleanup, client, testClient := setupClusterAndAgent(t, coreConfig)
	defer cleanup()

	err := client.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Test proxy by issuing two different requests
	{
		// Write data to the lease-kv backend
		_, err := testClient.Logical().Write("kv/foo", map[string]interface{}{
			"value": "bar",
			"ttl":   "1h",
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = testClient.Logical().Write("kv/foobar", map[string]interface{}{
			"value": "bar",
			"ttl":   "1h",
		})
		if err != nil {
			t.Fatal(err)
		}

		firstResp, err := testClient.Logical().Read("kv/foo")
		if err != nil {
			t.Fatal(err)
		}

		secondResp, err := testClient.Logical().Read("kv/foobar")
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(firstResp, secondResp); diff == nil {
			t.Logf("response: %#v", firstResp)
			t.Fatal("expected proxied responses, got cached response on second request")
		}
	}

	// Test caching behavior by issue the same request twice
	{
		_, err := testClient.Logical().Write("kv/baz", map[string]interface{}{
			"value": "foo",
			"ttl":   "1h",
		})
		if err != nil {
			t.Fatal(err)
		}

		proxiedResp, err := testClient.Logical().Read("kv/baz")
		if err != nil {
			t.Fatal(err)
		}

		cachedResp, err := testClient.Logical().Read("kv/baz")
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(proxiedResp, cachedResp); diff != nil {
			t.Fatal(diff)
		}
	}
}
