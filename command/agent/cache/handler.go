package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/consts"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
)

type Config struct {
	Token            string
	Proxier          Proxier
	UseAutoAuthToken bool
	Listeners        []net.Listener
	Logger           hclog.Logger
}

func Run(ctx context.Context, config *Config) error {
	// Create the API proxier
	apiProxy := NewAPIProxy(&APIProxyConfig{
		Logger: config.Logger.Named("apiproxy"),
	})

	// Create the lease cache proxier and set its underlying proxier to
	// the API proxier.
	leaseCache, err := NewLeaseCache(&LeaseCacheConfig{
		BaseContext: ctx,
		Proxier:     apiProxy,
		Logger:      config.Logger.Named("leasecache"),
	})
	if err != nil {
		return fmt.Errorf("failed to create lease cache: %v", err)
	}

	config.Proxier = leaseCache

	// Create a muxer and add paths relevant for the lease cache layer
	mux := http.NewServeMux()
	mux.Handle("/v1/agent/cache-clear", leaseCache.HandleCacheClear(ctx))

	mux.Handle("/", handler(ctx, config))
	for _, ln := range config.Listeners {
		server := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			ErrorLog:          config.Logger.StandardLogger(nil),
		}
		go server.Serve(ln)
	}

	return nil
}

func handler(ctx context.Context, config *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config.Logger.Info("received request", "path", r.URL.Path)

		token := r.Header.Get(consts.AuthHeaderName)
		if token == "" && config.UseAutoAuthToken {
			token = config.Token
		}

		// Parse and reset body.
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			config.Logger.Error("failed to read request body")
			respondError(w, http.StatusInternalServerError, errors.New("failed to read request body"))
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))

		resp, err := config.Proxier.Send(ctx, &SendRequest{
			Token:       token,
			Request:     r,
			RequestBody: reqBody,
		})
		if err != nil {
			respondError(w, http.StatusInternalServerError, errwrap.Wrapf("failed to get the response: {{err}}", err))
			return
		}

		copyHeader(w.Header(), resp.Response.Header)
		w.WriteHeader(resp.Response.StatusCode)
		io.Copy(w, resp.Response.Body)
		return
	})
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func respondError(w http.ResponseWriter, status int, err error) {
	logical.AdjustErrorStatusCode(&status, err)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := &vaulthttp.ErrorResponse{Errors: make([]string, 0, 1)}
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
	}

	enc := json.NewEncoder(w)
	enc.Encode(resp)
}
