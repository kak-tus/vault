package cachememdb

import "context"

type ContextInfo struct {
	Ctx        context.Context
	CancelFunc context.CancelFunc
	DoneCh     chan struct{}
}

// Index holds the response to be cached along with multiple other values that
// serve as pointers to refer back to this index.
type Index struct {
	// ID is a value that uniquely represents the request held by this
	// index. This is computed by serializing and hashing the response object.
	// Required: true, Unique: true
	ID string

	// Token is the token that fetched the response held by this index
	// Required: true, Unique: false
	Token string

	// TokenParent is the parent token of the token held by this index
	// Required: false, Unique: false
	TokenParent string

	// TokenAccessor is the accessor of the token being cached in this index
	// Required: true, Unique: false
	TokenAccessor string

	// Namespace is the namespace that was provided in the request path as the
	// Vault namespace to query
	Namespace string

	// RequestPath is the path of the request that resulted in the response
	// held by this index.
	// Required: true, Unique: false
	RequestPath string

	// Lease is the identifier of the lease in Vault, that belongs to the
	// response held by this index.
	// Required: false, Unique: true
	Lease string

	// Response is the serialized response object that the agent is caching.
	Response []byte

	// RenewCtxInfo holds the context and the corresponding cancel func for the
	// goroutine that manages the renewal of the secret belonging to the
	// response in this index.
	RenewCtxInfo *ContextInfo
}

type IndexName uint32

const (
	IndexNameInvalid IndexName = iota
	IndexNameID
	IndexNameLease
	IndexNameRequestPath
	IndexNameToken
	IndexNameTokenAccessor
	IndexNameTokenParent
)

func (indexName IndexName) String() string {
	switch indexName {
	case IndexNameID:
		return "id"
	case IndexNameLease:
		return "lease"
	case IndexNameRequestPath:
		return "request_path"
	case IndexNameToken:
		return "token"
	case IndexNameTokenAccessor:
		return "token_accessor"
	case IndexNameTokenParent:
		return "token_parent"
	}
	return ""
}

func indexNameFromString(indexName string) IndexName {
	switch indexName {
	case "id":
		return IndexNameID
	case "lease":
		return IndexNameLease
	case "request_path":
		return IndexNameRequestPath
	case "token":
		return IndexNameToken
	case "token_accessor":
		return IndexNameTokenAccessor
	case "token_parent":
		return IndexNameTokenParent
	default:
		return IndexNameInvalid
	}
}
