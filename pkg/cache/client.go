package cache

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/pkg/errors"
)

type Cache interface {
	AddImage(trustPolicy string, imageRef string, result types.ImageInfo) error

	GetImage(trustPolicy string, imageRef string) (*types.ImageInfo, bool)

	AddAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) error

	GetAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) bool

	Clear()
}

const (
	cacheEntry = "true"
)

type cache struct {
	useCache  bool
	ttl       time.Duration
	maxSize   int64
	ristretto *ristretto.Cache
}

type Option = func(*cache) error

func New(options ...Option) (Cache, error) {
	cache := &cache{
		ttl:     1 * time.Hour,
		maxSize: 1000,
	}
	for _, opt := range options {
		if err := opt(cache); err != nil {
			return nil, err
		}
	}

	config := &ristretto.Config{
		NumCounters: cache.maxSize * 10,
	}

	ristretto, err := ristretto.NewCache(config)
	if err != nil {
		return nil, err
	}

	cache.ristretto = ristretto

	return cache, nil
}

func WithCacheEnabled(b bool) Option {
	return func(c *cache) error {
		c.useCache = b
		return nil
	}
}

func WithMaxSize(s int64) Option {
	return func(c *cache) error {
		c.maxSize = s
		return nil
	}
}

func WithTTLDuration(t time.Duration) Option {
	return func(c *cache) error {
		c.ttl = t
		return nil
	}
}

func (c *cache) AddImage(trustPolicy string, imageRef string, result types.ImageInfo) error {
	if !c.useCache {
		return nil
	}

	key := createImageKey(trustPolicy, imageRef)

	val, err := json.Marshal(result)
	if err != nil {
		return err
	}

	if ok := c.ristretto.SetWithTTL(key, val, 0, c.ttl); !ok {
		return errors.Errorf("could not create cache entry for key=%s", key)
	}
	return nil
}

func (c *cache) GetImage(trustPolicy string, imageRef string) (*types.ImageInfo, bool) {
	if !c.useCache {
		return nil, false
	}

	key := createImageKey(trustPolicy, imageRef)
	entry, ok := c.ristretto.Get(key)

	if !ok {
		return nil, false
	}

	var val types.ImageInfo
	if val, ok = entry.(types.ImageInfo); !ok {
		return nil, false
	}
	return &val, true
}

func (c *cache) AddAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) error {
	if !c.useCache {
		return nil
	}

	key, err := createAttestationKey(trustPolicy, imageRef, attestationType, conditions)
	if err != nil {
		return err
	}

	if ok := c.ristretto.SetWithTTL(key, []byte(cacheEntry), 0, c.ttl); !ok {
		return errors.Errorf("could not create cache entry for key=%s", key)
	}
	return nil
}

func (c *cache) GetAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) bool {
	if !c.useCache {
		return false
	}

	key, err := createAttestationKey(trustPolicy, imageRef, attestationType, conditions)
	if err != nil {
		return false
	}
	entry, found := c.ristretto.Get(key)
	if !found || entry.(string) != cacheEntry {
		return false
	}
	return true
}

func (c *cache) Clear() {
	if !c.useCache {
		return
	}

	c.ristretto.Clear()
}

func createImageKey(trustPolicy string, imageRef string) string {
	return fmt.Sprintf("%s;%s", trustPolicy, imageRef)
}

func createAttestationKey(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) (string, error) {
	c, err := json.Marshal(conditions)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s;%s;%s;%s", trustPolicy, imageRef, attestationType, string(c)), nil
}
