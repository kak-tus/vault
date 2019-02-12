package cache

import (
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/helper/namespace"
)

func TestCache_APIProxy(t *testing.T) {
	cleanup, client, _ := setupClusterAndAgent(t, nil)
	defer cleanup()

	proxier := NewAPIProxy(&APIProxyConfig{
		Logger: logging.NewVaultLogger(hclog.Trace),
	})

	r := client.NewRequest("GET", "/v1/sys/health")
	req, err := r.ToRetryableHTTP()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := proxier.Send(namespace.RootContext(nil), &SendRequest{
		Request: req.Request,
	})
	if err != nil {
		t.Fatal(err)
	}

	var result api.HealthResponse
	err = jsonutil.DecodeJSONFromReader(resp.Response.Body, &result)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Initialized || result.Sealed || result.Standby {
		t.Fatalf("bad sys/health response")
	}
}
