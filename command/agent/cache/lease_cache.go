package cache

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	cachememdb "github.com/hashicorp/vault/command/agent/cache/cachememdb"
	"github.com/hashicorp/vault/helper/consts"
	"github.com/hashicorp/vault/helper/jsonutil"
	nshelper "github.com/hashicorp/vault/helper/namespace"
)

const (
	vaultPathTokenCreate         = "/v1/auth/token/create"
	vaultPathTokenRevoke         = "/v1/auth/token/revoke"
	vaultPathTokenRevokeSelf     = "/v1/auth/token/revoke-self"
	vaultPathTokenRevokeAccessor = "/v1/auth/token/revoke-accessor"
	vaultPathTokenRevokeOrphan   = "/v1/auth/token/revoke-orphan"
	vaultPathLeaseRevoke         = "/v1/sys/leases/revoke"
	vaultPathLeaseRevokeForce    = "/v1/sys/leases/revoke-force"
	vaultPathLeaseRevokePrefix   = "/v1/sys/leases/revoke-prefix"
)

var (
	contextIndexID  = contextIndex{}
	errInvalidType  = errors.New("invalid type provided")
	revocationPaths = []string{
		strings.TrimPrefix(vaultPathTokenRevoke, "/v1"),
		strings.TrimPrefix(vaultPathTokenRevokeSelf, "/v1"),
		strings.TrimPrefix(vaultPathTokenRevokeAccessor, "/v1"),
		strings.TrimPrefix(vaultPathTokenRevokeOrphan, "/v1"),
		strings.TrimPrefix(vaultPathLeaseRevoke, "/v1"),
		strings.TrimPrefix(vaultPathLeaseRevokeForce, "/v1"),
		strings.TrimPrefix(vaultPathLeaseRevokePrefix, "/v1"),
	}
)

type contextIndex struct{}

type cacheClearRequest struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Namespace string `json:"namespace"`
}

// LeaseCache is an implementation of Proxier that handles
// the caching of responses. It passes the incoming request
// to an underlying Proxier implementation.
type LeaseCache struct {
	proxier       Proxier
	logger        hclog.Logger
	db            *cachememdb.CacheMemDB
	rand          *rand.Rand
	tokenContexts map[string]*ContextInfo
	baseCtxInfo   *ContextInfo
}

// LeaseCacheConfig is the configuration for initializing a new
// Lease.
type LeaseCacheConfig struct {
	BaseContext context.Context
	Proxier     Proxier
	Logger      hclog.Logger
}

// ContextInfo holds a derived context and cancelFunc pair.
type ContextInfo struct {
	Ctx        context.Context
	CancelFunc context.CancelFunc
	DoneCh     chan struct{}
}

// NewLeaseCache creates a new instance of a LeaseCache.
func NewLeaseCache(conf *LeaseCacheConfig) (*LeaseCache, error) {
	if conf == nil {
		return nil, errors.New("nil configuration provided")
	}

	if conf.Proxier == nil || conf.Logger == nil {
		return nil, fmt.Errorf("missing configuration required params: %v", conf)
	}

	db, err := cachememdb.New()
	if err != nil {
		return nil, err
	}

	// Create a base context for the lease cache layer
	baseCtx, baseCancelFunc := context.WithCancel(conf.BaseContext)
	baseCtxInfo := &ContextInfo{
		Ctx:        baseCtx,
		CancelFunc: baseCancelFunc,
	}

	return &LeaseCache{
		proxier:       conf.Proxier,
		logger:        conf.Logger,
		db:            db,
		rand:          rand.New(rand.NewSource(int64(time.Now().Nanosecond()))),
		tokenContexts: make(map[string]*ContextInfo),
		baseCtxInfo:   baseCtxInfo,
	}, nil
}

// Send performs a cache lookup on the incoming request. If it's a cache hit,
// it will return the cached response, otherwise it will delegate to the
// underlying Proxier and cache the received response.
func (c *LeaseCache) Send(ctx context.Context, req *SendRequest) (*SendResponse, error) {
	// Compute the index ID
	id, err := computeIndexID(req)
	if err != nil {
		c.logger.Error("failed to compute cache key", "error", err)
		return nil, err
	}

	// Check if the response for this request is already in the cache
	index, err := c.db.Get(cachememdb.IndexNameID.String(), id)
	if err != nil {
		return nil, err
	}

	// Cached request is found, deserialize the response and return early
	if index != nil {
		c.logger.Debug("returning cached response", "path", req.Request.URL.Path)

		reader := bufio.NewReader(bytes.NewReader(index.Response))
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			c.logger.Error("failed to deserialize response", "error", err)
			return nil, err
		}

		return &SendResponse{
			Response: &api.Response{
				Response: resp,
			},
		}, nil
	}

	c.logger.Debug("forwarding the request and caching the response", "path", req.Request.URL.Path)

	// Pass the request down and get a response
	resp, err := c.proxier.Send(ctx, req)
	if err != nil {
		return nil, err
	}

	// Get the namespace from the request header
	namespace := req.Request.Header.Get(consts.NamespaceHeaderName)
	// We need to populate an empty value since go-memdb will skip over indexes
	// that contain empty values.
	if namespace == "" {
		namespace = "root/"
	}

	// Build the index to cache based on the response received
	index = &cachememdb.Index{
		ID:          id,
		Namespace:   namespace,
		RequestPath: req.Request.URL.Path,
	}

	secret, err := api.ParseSecret(bytes.NewBuffer(resp.ResponseBody))
	if err != nil {
		c.logger.Error("failed to parse response as secret", "error", err)
		return nil, err
	}

	isRevocation, err := c.handleRevocationRequest(ctx, req, resp)
	if err != nil {
		c.logger.Error("failed to process the response", "error", err)
		return nil, err
	}

	// If this is a revocation request, do not go through cache logic.
	if isRevocation {
		return resp, nil
	}

	var renewCtxInfo *ContextInfo
	switch {
	case secret == nil:
		// Fast path for non-cacheable responses
		return resp, nil
	case secret.LeaseID != "":
		renewCtxInfo = c.tokenContexts[req.Token]
		// If the lease belongs to a token that is not managed by the agent,
		// return the response without caching it.
		if renewCtxInfo == nil {
			return resp, nil
		}

		// Derive a context for renewal using the token's context
		newCtxInfo := new(ContextInfo)
		newCtxInfo.Ctx, newCtxInfo.CancelFunc = context.WithCancel(renewCtxInfo.Ctx)
		newCtxInfo.DoneCh = make(chan struct{})
		renewCtxInfo = newCtxInfo

		index.Lease = secret.LeaseID
		index.Token = req.Token

	case secret.Auth != nil:
		isNonOrphanNewToken := strings.HasPrefix(req.Request.URL.Path, vaultPathTokenCreate) && resp.Response.StatusCode == http.StatusOK && !secret.Auth.Orphan

		// If the new token is a result of token creation endpoints (not from
		// login endpoints), and if its a non-orphan, then the new token's
		// context should be derived from the context of the parent token.
		var parentCtx context.Context
		if isNonOrphanNewToken {
			parentCtxInfo := c.tokenContexts[req.Token]
			// If parent token is not managed by the agent, child shouldn't be
			// either.
			if parentCtxInfo == nil {
				return resp, nil
			}
			parentCtx = parentCtxInfo.Ctx
			index.TokenParent = req.Token
		}

		renewCtxInfo = c.createCtxInfo(parentCtx, secret.Auth.ClientToken)
		index.Token = secret.Auth.ClientToken
		index.TokenAccessor = secret.Auth.Accessor

	default:
		// We shouldn't be hitting this, but will err on the side of caution and
		// simply proxy.
		return resp, nil
	}

	// Serialize the response to store it in the cached index
	var respBytes bytes.Buffer
	err = resp.Response.Write(&respBytes)
	if err != nil {
		c.logger.Error("failed to serialize response", "error", err)
		return nil, err
	}

	// Reset the response body for upper layers to read
	resp.Response.Body = ioutil.NopCloser(bytes.NewBuffer(resp.ResponseBody))

	// Set the index's Response
	index.Response = respBytes.Bytes()

	// Store the index ID in the renewer context
	renewCtx := context.WithValue(renewCtxInfo.Ctx, contextIndexID, index.ID)

	// Store the renewer context in the index
	index.RenewCtxInfo = &cachememdb.ContextInfo{
		Ctx:        renewCtx,
		CancelFunc: renewCtxInfo.CancelFunc,
		DoneCh:     renewCtxInfo.DoneCh,
	}

	// Short-circuit if the secret is not renewable
	tokenRenewable, err := secret.TokenIsRenewable()
	if err != nil {
		c.logger.Error("failed to parse renewable param", "error", err)
		return nil, err
	}
	if !secret.Renewable && !tokenRenewable {
		c.logger.Debug("secret not renewable, skipping addtion to the renewer")
		return resp, nil
	}

	c.logger.Debug("storing response into the cache and starting the secret renewal")

	// Store the index in the cache
	err = c.db.Set(index)
	if err != nil {
		c.logger.Error("failed to cache the proxied response", "error", err)
		return nil, err
	}

	// Start renewing the secret in the response
	go c.startRenewing(renewCtx, index, req, secret)

	return resp, nil
}

func (c *LeaseCache) createCtxInfo(ctx context.Context, token string) *ContextInfo {
	if ctx == nil {
		ctx = c.baseCtxInfo.Ctx
	}
	ctxInfo := new(ContextInfo)
	ctxInfo.Ctx, ctxInfo.CancelFunc = context.WithCancel(ctx)
	ctxInfo.DoneCh = make(chan struct{})
	c.tokenContexts[token] = ctxInfo
	return ctxInfo
}

func (c *LeaseCache) startRenewing(ctx context.Context, index *cachememdb.Index, req *SendRequest, secret *api.Secret) {
	defer func() {
		id := ctx.Value(contextIndexID).(string)
		c.logger.Debug("evicting index from cache", "id", id)
		err := c.db.Evict(cachememdb.IndexNameID.String(), id)
		if err != nil {
			c.logger.Error("failed to evict index", "id", id, "error", err)
			return
		}
	}()

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		c.logger.Error("failed to create API client in the renewer", "error", err)
		return
	}
	client.SetToken(req.Token)
	client.SetHeaders(req.Request.Header)

	renewer, err := client.NewRenewer(&api.RenewerInput{
		Secret: secret,
	})
	if err != nil {
		c.logger.Error("failed to create secret renewer", "error", err)
		return
	}

	c.logger.Debug("initiating renewal", "path", req.Request.URL.Path)
	go renewer.Renew()
	defer renewer.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("shutdown triggered, stopping renewer", "path", req.Request.URL.Path)
			return
		case err := <-renewer.DoneCh():
			if err != nil {
				c.logger.Error("failed to renew secret", "error", err)
				return
			}
			c.logger.Debug("renewal halted; evicting from cache", "path", req.Request.URL.Path)
			return
		case renewal := <-renewer.RenewCh():
			c.logger.Debug("renewal received; updating cache", "path", req.Request.URL.Path)
			err = c.updateResponse(ctx, renewal)
			if err != nil {
				c.logger.Error("failed to handle renewal", "error", err)
				return
			}
		case <-index.RenewCtxInfo.DoneCh:
			c.logger.Debug("done channel closed")
			return
		}
	}
}

func (c *LeaseCache) updateResponse(ctx context.Context, renewal *api.RenewOutput) error {
	id := ctx.Value(contextIndexID).(string)

	// Get the cached index using the id in the context
	index, err := c.db.Get(cachememdb.IndexNameID.String(), id)
	if err != nil {
		return err
	}
	if index == nil {
		return fmt.Errorf("missing cache entry for id: %q", id)
	}

	// Read the response from the index
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(index.Response)), nil)
	if err != nil {
		c.logger.Error("failed to deserialize response", "error", err)
		return err
	}

	// Update the body in the reponse by the renewed secret
	bodyBytes, err := json.Marshal(renewal.Secret)
	if err != nil {
		return err
	}
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	// Serialize the response
	var respBytes bytes.Buffer
	err = resp.Write(&respBytes)
	if err != nil {
		c.logger.Error("failed to serialize updated response", "error", err)
		return err
	}

	// Update the response in the index and set it in the cache
	index.Response = respBytes.Bytes()
	err = c.db.Set(index)
	if err != nil {
		c.logger.Error("failed to cache the proxied response", "error", err)
		return err
	}

	return nil
}

// computeIndexID results in a value that uniquely identifies a request
// received by the agent. It does so by SHA256 hashing the serialized request
// object containing the request path, query parameters and body parameters.
func computeIndexID(req *SendRequest) (string, error) {
	var b bytes.Buffer

	// Serialze the request
	if err := req.Request.Write(&b); err != nil {
		return "", fmt.Errorf("failed to serialize request: %v", err)
	}

	// Reset the request body after it has been closed by Write
	req.Request.Body = ioutil.NopCloser(bytes.NewBuffer(req.RequestBody))

	// Append req.Token into the byte slice. This is needed since auto-auth'ed
	// requests sets the token directly into SendRequest.Token
	b.Write([]byte(req.Token))

	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// HandleCacheClear returns a handlerFunc that can perform cache clearing operations.
func (c *LeaseCache) HandleCacheClear(ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := new(cacheClearRequest)
		if err := jsonutil.DecodeJSONFromReader(r.Body, req); err != nil {
			if err == io.EOF {
				err = errors.New("empty JSON provided")
			}
			respondError(w, http.StatusBadRequest, errwrap.Wrapf("failed to parse JSON input: {{err}}", err))
			return
		}

		c.logger.Debug("received cache-clear request", "type", req.Type, "namespace", req.Namespace, "value", req.Value)

		if err := c.handleCacheClear(ctx, req.Type, req.Namespace, req.Value); err != nil {
			// Default to 500 on error, unless the user provided an invalid type,
			// which would then be a 400.
			httpStatus := http.StatusInternalServerError
			if err == errInvalidType {
				httpStatus = http.StatusBadRequest
			}
			respondError(w, httpStatus, errwrap.Wrapf("failed to clear cache: {{err}}", err))
			return
		}

		return
	})
}

func (c *LeaseCache) handleCacheClear(ctx context.Context, clearType string, clearValues ...interface{}) error {
	if len(clearValues) == 0 {
		return errors.New("no value(s) provided to clear corresponding cache entries")
	}

	// The value that we want to clear, for most cases, is the last one provided.
	clearValue, ok := clearValues[len(clearValues)-1].(string)
	if !ok {
		return fmt.Errorf("unable to convert %v to type string", clearValue)
	}

	switch clearType {
	case "request_path":
		// For this particular case, we need to ensure that there are 2 provided
		// indexers for the proper lookup.
		if len(clearValues) != 2 {
			return fmt.Errorf("clearing cache by request path requires 2 indexers, got %d", len(clearValues))
		}

		// The first value provided for this case will be the namespace, but if it's
		// an empty value we need to overwrite it with "root/" to ensure proper
		// cache lookup.
		if clearValues[0].(string) == "" {
			clearValues[0] = "root/"
		}

		// Find all the cached entries which has the given request path and
		// cancel the contexts of all the respective renewers
		indexes, err := c.db.GetByPrefix(clearType, clearValues...)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			index.RenewCtxInfo.CancelFunc()
		}

	case "token":
		if clearValue == "" {
			return nil
		}
		// Get the context for the given token and cancel its context
		tokenCtxInfo := c.tokenContexts[clearValue]
		if tokenCtxInfo == nil {
			return nil
		}

		tokenCtxInfo.CancelFunc()

		// Remove the cancelled context from the map
		delete(c.tokenContexts, clearValue)

	case "token_accessor", "lease":
		// Get the cached index and cancel the corresponding renewer context
		index, err := c.db.Get(clearType, clearValue)
		if err != nil {
			return err
		}
		if index == nil {
			return nil
		}
		index.RenewCtxInfo.CancelFunc()

	case "all":
		// Cancel the base context which triggers all the goroutines to
		// stop and evict entries from cache.
		c.baseCtxInfo.CancelFunc()

		// Reset the base context
		baseCtx, baseCancel := context.WithCancel(ctx)
		c.baseCtxInfo = &ContextInfo{
			Ctx:        baseCtx,
			CancelFunc: baseCancel,
		}

		// Reset the memdb instance
		if err := c.db.Flush(); err != nil {
			return err
		}

	default:
		return errInvalidType
	}

	c.logger.Debug("successfully cleared matching cache entries")

	return nil
}

// handleRevocationRequest checks whether the originating request is a
// revocation request, and if so perform applicable cache cleanups.
// Returns true is this is a revocation request.
func (c *LeaseCache) handleRevocationRequest(ctx context.Context, req *SendRequest, resp *SendResponse) (bool, error) {
	// Lease and token revocations return 204's on success. Fast-path if that's
	// not the case.
	if resp.Response.StatusCode != http.StatusNoContent {
		return false, nil
	}

	namespace, path := deriveNamespaceAndRevocationPath(req)

	switch {
	case path == vaultPathTokenRevoke:
		// Get the token from the request body
		jsonBody := map[string]interface{}{}
		if err := json.Unmarshal(req.RequestBody, &jsonBody); err != nil {
			return false, err
		}
		token, ok := jsonBody["token"]
		if !ok {
			return false, fmt.Errorf("failed to get token from request body")
		}

		// Clear the cache entry associated with the token and all the other
		// entries belonging to the leases derived from this token.
		if err := c.handleCacheClear(ctx, "token", token.(string)); err != nil {
			return false, err
		}

	case path == vaultPathTokenRevokeSelf:
		// Clear the cache entry associated with the token and all the other
		// entries belonging to the leases derived from this token.
		if err := c.handleCacheClear(ctx, "token", req.Token); err != nil {
			return false, err
		}

	case path == vaultPathTokenRevokeAccessor:
		jsonBody := map[string]interface{}{}
		if err := json.Unmarshal(req.RequestBody, &jsonBody); err != nil {
			return false, err
		}
		accessor, ok := jsonBody["accessor"]
		if !ok {
			return false, fmt.Errorf("failed to get accessor from request body")
		}

		if err := c.handleCacheClear(ctx, "token_accessor", accessor.(string)); err != nil {
			return false, err
		}

	case path == vaultPathTokenRevokeOrphan:
		jsonBody := map[string]interface{}{}
		if err := json.Unmarshal(req.RequestBody, &jsonBody); err != nil {
			return false, err
		}
		token, ok := jsonBody["token"]
		if !ok {
			return false, fmt.Errorf("failed to get token from request body")
		}

		// Find out all the indexes that are directly tied to the revoked token
		indexes, err := c.db.GetByPrefix(cachememdb.IndexNameToken.String(), token.(string))
		if err != nil {
			return false, err
		}

		// Out of these indexes, one will be for the token itself and the rest
		// will be for leases of this token. Cancel the contexts of all the
		// leases and return from renewer goroutine for the token's index
		// without cancelling the context. Cancelling the context of the
		// token's renewer will evict all the child tokens which is not
		// desired.
		for _, index := range indexes {
			if index.Lease != "" {
				index.RenewCtxInfo.CancelFunc()
			} else {
				close(index.RenewCtxInfo.DoneCh)
			}
		}

		// Clear the parent references of the revoked token
		indexes, err = c.db.GetByPrefix(cachememdb.IndexNameTokenParent.String(), token.(string))
		if err != nil {
			return false, err
		}
		for _, index := range indexes {
			index.TokenParent = ""
			err = c.db.Set(index)
			if err != nil {
				c.logger.Error("failed to persist index", "error", err)
				return false, err
			}
		}

	case path == vaultPathLeaseRevoke:
		// TODO: Should lease present in the URL itself be considered here?
		// Get the lease from the request body
		jsonBody := map[string]interface{}{}
		if err := json.Unmarshal(req.RequestBody, &jsonBody); err != nil {
			return false, err
		}
		leaseID, ok := jsonBody["lease_id"]
		if !ok {
			return false, fmt.Errorf("failed to get lease_id from request body")
		}
		if err := c.handleCacheClear(ctx, "lease", leaseID.(string)); err != nil {
			return false, err
		}

	case strings.HasPrefix(path, vaultPathLeaseRevokeForce):
		// Trim the URL path to get the request path prefix
		prefix := strings.TrimPrefix(path, vaultPathLeaseRevokeForce)
		// Get all the cache indexes that use the request path containing the
		// prefix and cancel the renewer context of each.
		indexes, err := c.db.GetByPrefix("request_path", namespace, "/v1"+prefix)
		if err != nil {
			return false, err
		}
		for _, index := range indexes {
			index.RenewCtxInfo.CancelFunc()
		}

	case strings.HasPrefix(path, vaultPathLeaseRevokePrefix):
		// Trim the URL path to get the request path prefix
		prefix := strings.TrimPrefix(path, vaultPathLeaseRevokePrefix)
		// Get all the cache indexes that use the request path containing the
		// prefix and cancel the renewer context of each.
		indexes, err := c.db.GetByPrefix("request_path", namespace, "/v1"+prefix)
		if err != nil {
			return false, err
		}
		for _, index := range indexes {
			index.RenewCtxInfo.CancelFunc()
		}

	default:
		return false, nil
	}

	c.logger.Debug("triggered caching eviction from revocation request")

	return true, nil
}

// deriveNamespaceAndRevocationPath returns the namespace and relative path for
// revocation paths.
//
// If the path contains a namespace, but it's not a revocation path, it will be
// returned as-is, since there's no way to tell where the namespace ends and
// where the request path begins purely based off a string.
//
// Case 1: /v1/ns1/leases/revoke  -> ns1/, /v1/leases/revoke
// Case 2: ns1/ /v1/leases/revoke -> ns1/, /v1/leases/revoke
// Case 3: /v1/ns1/foo/bar  -> root/, /v1/ns1/foo/bar
// Case 4: ns1/ /v1/foo/bar -> ns1/, /v1/foo/bar
func deriveNamespaceAndRevocationPath(req *SendRequest) (string, string) {
	namespace := "root/"
	nsHeader := req.Request.Header.Get(consts.NamespaceHeaderName)
	if nsHeader != "" {
		namespace = nsHeader
	}

	fullPath := req.Request.URL.Path
	nonVersionedPath := strings.TrimPrefix(fullPath, "/v1")

	for _, pathToCheck := range revocationPaths {
		// We use strings.Contains here for paths that can contain
		// vars in the path, e.g. /v1/lease/revoke-prefix/:prefix
		i := strings.Index(nonVersionedPath, pathToCheck)
		// If there's no match, move on to the next check
		if i == -1 {
			continue
		}

		// If the index is 0, this is a relative path with no namespace preppended,
		// so we can break early
		if i == 0 {
			break
		}

		// We need to turn /ns1 into ns1/, this makes it easy
		namespaceInPath := nshelper.Canonicalize(nonVersionedPath[:i])

		// If it's root, we replace, otherwise we join
		if namespace == "root/" {
			namespace = namespaceInPath
		} else {
			namespace = namespace + namespaceInPath
		}

		return namespace, fmt.Sprintf("/v1%s", nonVersionedPath[i:])
	}

	return namespace, fmt.Sprintf("/v1%s", nonVersionedPath)
}
