package cache

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/nirmata/kyverno-notation-verifier/types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
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
	log       *zap.SugaredLogger
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

	if cache.maxSize == 0 {
		cache.maxSize = 1000
	}
	config := &ristretto.Config{
		NumCounters: cache.maxSize * 10,
		MaxCost:     1 << 30,
		BufferItems: 64,
	}

	ristretto, err := ristretto.NewCache(config)
	if err != nil {
		return nil, err
	}

	cache.ristretto = ristretto

	if cache.log == nil {
		cache.log = zap.NewNop().Sugar()
	}

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

func WithLogger(l *zap.SugaredLogger) Option {
	return func(c *cache) error {
		c.log = l
		return nil
	}
}

func (c *cache) AddImage(trustPolicy string, imageRef string, result types.ImageInfo) error {
	c.log.Infof("Adding image to the cache: trustPolicy=%s, imageRef=%s, result=%v", trustPolicy, imageRef, result)
	if !c.useCache {
		c.log.Infof("Cache is disabled not adding image")
		return nil
	}

	key := createImageKey(trustPolicy, imageRef)

	val, err := json.Marshal(result)
	if err != nil {
		c.log.Errorf("could not marshal image info imageInfo=%v", result)
		return err
	}

	if ok := c.ristretto.SetWithTTL(key, val, 0, c.ttl); !ok {
		c.log.Errorf("could not create cache entry for key=%s", key)
		return errors.Errorf("could not create cache entry for key=%s", key)
	}
	return nil
}

func (c *cache) GetImage(trustPolicy string, imageRef string) (*types.ImageInfo, bool) {
	c.log.Infof("Getting image from the cache: trustPolicy=%s, imageRef=%s", trustPolicy, imageRef)
	if !c.useCache {
		c.log.Infof("Cache is disabled not getting image")
		return nil, false
	}

	key := createImageKey(trustPolicy, imageRef)
	entry, ok := c.ristretto.Get(key)

	if !ok {
		c.log.Errorf("Entry not found key=%s", key)
		return nil, false
	}

	var val types.ImageInfo
	if val, ok = entry.(types.ImageInfo); !ok {
		return nil, false
	}
	return &val, true
}

func (c *cache) AddAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) error {
	c.log.Infof("Adding adding attestations to the cache: trustPolicy=%s, imageRef=%s, attestationType=%s, conditions=%v ", trustPolicy, imageRef, attestationType, conditions)
	if !c.useCache {
		c.log.Infof("Cache is disabled not adding attestations")
		return nil
	}

	key, err := createAttestationKey(trustPolicy, imageRef, attestationType, conditions)
	if err != nil {
		c.log.Errorf("Failed to create key, error=%v", err.Error())
		return err
	}

	if ok := c.ristretto.SetWithTTL(key, []byte(cacheEntry), 0, c.ttl); !ok {
		c.log.Errorf("could not create cache entry for key=%s", key)
		return errors.Errorf("could not create cache entry for key=%s", key)
	}
	return nil
}

func (c *cache) GetAttestation(trustPolicy string, imageRef string, attestationType string, conditions []kyvernov1.AnyAllConditions) bool {
	c.log.Infof("Getting adding attestations from the cache: trustPolicy=%s, imageRef=%s, attestationType=%s, conditions=%v ", trustPolicy, imageRef, attestationType, conditions)
	if !c.useCache {
		c.log.Infof("Cache is disabled not getting attestations")
		return false
	}

	key, err := createAttestationKey(trustPolicy, imageRef, attestationType, conditions)
	if err != nil {
		c.log.Errorf("Failed to create key, error=%v", err.Error())
		return false
	}
	_, found := c.ristretto.Get(key)
	if !found {
		c.log.Errorf("Entry not found")
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
