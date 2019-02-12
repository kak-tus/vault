package cachememdb

import (
	"errors"
	"fmt"

	memdb "github.com/hashicorp/go-memdb"
)

const (
	tableNameIndexer = "indexer"
)

// CacheMemDB is the underlying cache database for storing indexes.
type CacheMemDB struct {
	db *memdb.MemDB
}

// New creates a new instance of CacheMemDB.
func New() (*CacheMemDB, error) {
	db, err := newDB()
	if err != nil {
		return nil, err
	}

	return &CacheMemDB{
		db: db,
	}, nil
}

func newDB() (*memdb.MemDB, error) {
	cacheSchema := &memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			tableNameIndexer: &memdb.TableSchema{
				Name: tableNameIndexer,
				Indexes: map[string]*memdb.IndexSchema{
					IndexNameID.String(): &memdb.IndexSchema{
						Name:   IndexNameID.String(),
						Unique: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "ID",
						},
					},
					IndexNameRequestPath.String(): &memdb.IndexSchema{
						Name:   IndexNameRequestPath.String(),
						Unique: false,
						Indexer: &memdb.CompoundIndex{
							Indexes: []memdb.Indexer{
								&memdb.StringFieldIndex{
									Field: "Namespace",
								},
								&memdb.StringFieldIndex{
									Field: "RequestPath",
								},
							},
						},
					},
					IndexNameToken.String(): &memdb.IndexSchema{
						Name:   IndexNameToken.String(),
						Unique: false,
						Indexer: &memdb.StringFieldIndex{
							Field: "Token",
						},
					},
					IndexNameTokenParent.String(): &memdb.IndexSchema{
						Name:         IndexNameTokenParent.String(),
						Unique:       false,
						AllowMissing: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "TokenParent",
						},
					},
					IndexNameTokenAccessor.String(): &memdb.IndexSchema{
						Name:         IndexNameTokenAccessor.String(),
						Unique:       false,
						AllowMissing: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "TokenAccessor",
						},
					},
					IndexNameLease.String(): &memdb.IndexSchema{
						Name:         IndexNameLease.String(),
						Unique:       true,
						AllowMissing: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "Lease",
						},
					},
				},
			},
		},
	}

	db, err := memdb.NewMemDB(cacheSchema)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// GetByPrefix returns all the cached indexes based on the index name and the
// value prefix.
func (c *CacheMemDB) GetByPrefix(indexName string, indexValues ...interface{}) ([]*Index, error) {
	if indexNameFromString(indexName) == IndexNameInvalid {
		return nil, fmt.Errorf("invalid index name %q", indexName)
	}

	indexName = indexName + "_prefix"

	// Get all the objects
	iter, err := c.db.Txn(false).Get(tableNameIndexer, indexName, indexValues...)
	if err != nil {
		return nil, err
	}

	var indexes []*Index
	for {
		obj := iter.Next()
		if obj == nil {
			break
		}
		index, ok := obj.(*Index)
		if !ok {
			return nil, fmt.Errorf("failed to cast cached index")
		}

		indexes = append(indexes, index)
	}

	return indexes, nil
}

// Get returns the index based on the indexer and the index values provided.
func (c *CacheMemDB) Get(indexName string, indexValues ...interface{}) (*Index, error) {
	if indexNameFromString(indexName) == IndexNameInvalid {
		return nil, fmt.Errorf("invalid index name %q", indexName)
	}

	raw, err := c.db.Txn(false).First(tableNameIndexer, indexName, indexValues...)
	if err != nil {
		return nil, err
	}

	if raw == nil {
		return nil, nil
	}

	index, ok := raw.(*Index)
	if !ok {
		return nil, errors.New("unable to parse index value from the cache")
	}

	return index, nil
}

// Set stores the index into the cache.
func (c *CacheMemDB) Set(index *Index) error {
	if index == nil {
		return errors.New("nil index provided")
	}

	txn := c.db.Txn(true)
	defer txn.Abort()

	if err := txn.Insert(tableNameIndexer, index); err != nil {
		return fmt.Errorf("unable to insert index into cache: %v", err)
	}

	txn.Commit()

	return nil
}

// Evict removes an index from the cache based on index name and value.
func (c *CacheMemDB) Evict(indexName string, indexValues ...interface{}) error {
	index, err := c.Get(indexName, indexValues...)
	if err != nil {
		return fmt.Errorf("unable to fetch index on cache deletion: %v", err)
	}

	if index == nil {
		return nil
	}

	txn := c.db.Txn(true)
	defer txn.Abort()

	if err := txn.Delete(tableNameIndexer, index); err != nil {
		return fmt.Errorf("unable to delete index from cache: %v", err)
	}

	txn.Commit()

	return nil
}

// EvictAll removes all matching indexes from the cache based on index name and value.
func (c *CacheMemDB) EvictAll(indexName, indexValue string) error {
	return c.batchEvict(false, indexName, indexValue)
}

// EvictByPrefix removes all matching prefix indexes from the cache based on index name and prefix.
func (c *CacheMemDB) EvictByPrefix(indexName, indexPrefix string) error {
	return c.batchEvict(true, indexName, indexPrefix)
}

func (c *CacheMemDB) batchEvict(isPrefix bool, indexName string, indexValues ...interface{}) error {
	if indexNameFromString(indexName) == IndexNameInvalid {
		return fmt.Errorf("invalid index name %q", indexName)
	}

	if isPrefix {
		indexName = indexName + "_prefix"
	}

	txn := c.db.Txn(true)
	defer txn.Abort()

	_, err := txn.DeleteAll(tableNameIndexer, indexName, indexValues...)
	if err != nil {
		return err
	}

	txn.Commit()

	return nil
}

// Flush resets the underlying cache object.
func (c *CacheMemDB) Flush() error {
	newDB, err := newDB()
	if err != nil {
		return err
	}

	c.db = newDB

	return nil
}
