package cache

import (
	"testing"
	"time"

	"github.com/nirmata/kyverno-notation-verifier/pkg/types"
	"gotest.tools/assert"
)

func mustNegativeTestCache(t *testing.T, opts ...Option) Cache {
	t.Helper()
	opts = append([]Option{WithCacheEnabled(true)}, opts...)
	c, err := New(opts...)
	assert.NilError(t, err)
	return c
}

// waitForWrite blocks until ristretto applied the pending Set, otherwise the
// subsequent Get would be flaky (ristretto buffers writes).
func waitForWrite(c Cache) {
	if ic, ok := c.(*cache); ok {
		ic.ristretto.Wait()
	}
}

func TestAddGetFailureRoundTrip(t *testing.T) {
	c := mustNegativeTestCache(t)

	_, found := c.GetFailure("aws-signer-trust-policy", "registry.example.com/app:v1")
	assert.Equal(t, found, false)

	assert.NilError(t, c.AddFailure("aws-signer-trust-policy", "registry.example.com/app:v1", "no signature is associated with \"registry.example.com/app:v1\""))
	waitForWrite(c)

	reason, found := c.GetFailure("aws-signer-trust-policy", "registry.example.com/app:v1")
	assert.Equal(t, found, true)
	assert.Equal(t, reason, "no signature is associated with \"registry.example.com/app:v1\"")
}

func TestGetFailureMiss(t *testing.T) {
	c := mustNegativeTestCache(t)

	reason, found := c.GetFailure("policy", "image:tag")
	assert.Equal(t, found, false)
	assert.Equal(t, reason, "")
}

func TestNegativeCacheExpiry(t *testing.T) {
	c := mustNegativeTestCache(t, WithNegativeTTLDuration(50*time.Millisecond))

	assert.NilError(t, c.AddFailure("policy", "image:tag", "boom"))
	waitForWrite(c)

	_, found := c.GetFailure("policy", "image:tag")
	assert.Equal(t, found, true)

	time.Sleep(500 * time.Millisecond)

	_, found = c.GetFailure("policy", "image:tag")
	assert.Equal(t, found, false)
}

func TestPositiveAndNegativeEntriesDoNotCollide(t *testing.T) {
	c := mustNegativeTestCache(t)

	assert.NilError(t, c.AddImage("policy", "image:tag", types.Image{}))
	assert.NilError(t, c.AddFailure("policy", "image:tag", "no signature"))
	waitForWrite(c)

	_, found := c.GetImage("policy", "image:tag")
	assert.Equal(t, found, true)

	reason, found := c.GetFailure("policy", "image:tag")
	assert.Equal(t, found, true)
	assert.Equal(t, reason, "no signature")
}

func TestNegativeCacheDisabled(t *testing.T) {
	c, err := New(WithCacheEnabled(false))
	assert.NilError(t, err)

	assert.NilError(t, c.AddFailure("policy", "image:tag", "boom"))

	_, found := c.GetFailure("policy", "image:tag")
	assert.Equal(t, found, false)
}
