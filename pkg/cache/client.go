package cache

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/allegro/bigcache"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/nirmata/kyverno-notation-verifier/types"
)

type Cache interface {
	AddImage(trustPolicy string, imageRef string, result types.ImageInfo) error

	GetImage(trustPolicy string, imageRef string) (*types.ImageInfo, bool)

	AddAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) error

	GetAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) bool

	Clear() error
}

const (
	cacheEntry = "true"
)

type cache struct {
	ttl           time.Duration
	cleanupWindow time.Duration
	maxSize       int
	bigCache      *bigcache.BigCache
}

type Option = func(*cache) error

func New(options ...Option) (Cache, error) {
	cache := &cache{
		ttl:           1 * time.Hour,
		cleanupWindow: 30 * time.Minute,
		maxSize:       1000,
	}
	for _, opt := range options {
		if err := opt(cache); err != nil {
			return nil, err
		}
	}

	config := bigcache.Config{
		Shards:             8,
		LifeWindow:         cache.ttl,
		CleanWindow:        cache.cleanupWindow,
		MaxEntriesInWindow: 1000,
		MaxEntrySize:       cache.maxSize,
		Verbose:            true,
		HardMaxCacheSize:   cache.maxSize,
	}
	bigCache, err := bigcache.NewBigCache(config)
	if err != nil {
		return nil, err
	}

	cache.bigCache = bigCache

	return cache, nil
}

func WithMaxSize(s int) Option {
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

func WithCleanupWindow(t time.Duration) Option {
	return func(c *cache) error {
		c.cleanupWindow = t
		return nil
	}
}

func (c *cache) AddImage(trustPolicy string, imageRef string, result types.ImageInfo) error {
	key := createImageKey(trustPolicy, imageRef)

	val, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return c.bigCache.Set(key, val)
}

func (c *cache) GetImage(trustPolicy string, imageRef string) (*types.ImageInfo, bool) {
	key := createImageKey(trustPolicy, imageRef)
	entry, err := c.bigCache.Get(key)

	if err != nil {
		return nil, false
	}

	var val types.ImageInfo
	if err := json.Unmarshal(entry, &val); err != nil {
		return nil, false
	}
	return &val, true
}

func (c *cache) AddAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) error {
	key, err := createAttestationKey(trustPolicy, imageRef, attestationType, conditions)
	if err != nil {
		return err
	}
	return c.bigCache.Set(key, []byte(cacheEntry))
}

func (c *cache) GetAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) bool {
	key, err := createAttestationKey(trustPolicy, imageRef, attestationType, conditions)
	if err != nil {
		return false
	}
	entry, err := c.bigCache.Get(key)
	if err != nil || string(entry) != cacheEntry {
		return false
	}
	return true
}

func (c *cache) Clear() error {
	return c.bigCache.Reset()
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
