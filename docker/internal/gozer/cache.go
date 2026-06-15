package gozer

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache is the /check verdict cache, keyed on sha256(body). /report and /revoke
// are never cached. Two implementations exist: an in-process TTL+LRU map
// (default) and a Redis-backed cache (shared across distributed scanners) that
// fronts Redis with the same in-process map as an L1.
type Cache interface {
	// Get returns the cached verdict bytes and true on a live hit.
	Get(key string) ([]byte, bool)
	// Put stores verdict bytes under key for the configured TTL.
	Put(key string, val []byte)
}

// NewCache builds the cache backend for cfg. It returns nil (caching disabled)
// when CacheTTL <= 0. A Redis backend is used when RedisURL is set; if Redis
// cannot be initialised gozer logs and falls back to the in-process cache,
// so a misconfigured Redis never disables /check.
func NewCache(cfg *Config, logf func(string, ...any)) Cache {
	if cfg.CacheTTL <= 0 {
		return nil
	}
	mem := newMemCache(cfg.CacheSize, cfg.CacheTTL)
	if cfg.RedisURL == "" {
		return mem
	}
	rc, err := newRedisCache(cfg, mem)
	if err != nil {
		logf("Redis cache init failed (%v); using in-memory", err)
		return mem
	}
	return rc
}

// memCache is a TTL map with a size cap. On overflow it first drops expired
// entries, then evicts the soonest-to-expire entries until back under the cap
// (an approximate LRU — TTL is uniform, so oldest-inserted expires first).
type memCache struct {
	mu   sync.Mutex
	d    map[string]memEntry
	size int
	ttl  time.Duration
}

type memEntry struct {
	exp  time.Time
	data []byte
}

func newMemCache(size int, ttl time.Duration) *memCache {
	if size <= 0 {
		size = 4096
	}
	return &memCache{d: make(map[string]memEntry, size), size: size, ttl: ttl}
}

func (c *memCache) Get(key string) ([]byte, bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.d[key]
	if !ok {
		return nil, false
	}
	if now.After(e.exp) {
		delete(c.d, key)
		return nil, false
	}
	return e.data, true
}

func (c *memCache) Put(key string, val []byte) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.d) >= c.size {
		for k, e := range c.d {
			if now.After(e.exp) {
				delete(c.d, k)
			}
		}
		for len(c.d) >= c.size {
			var oldestK string
			var oldestExp time.Time
			first := true
			for k, e := range c.d {
				if first || e.exp.Before(oldestExp) {
					oldestK, oldestExp, first = k, e.exp, false
				}
			}
			if first { // map emptied concurrently
				break
			}
			delete(c.d, oldestK)
		}
	}
	c.d[key] = memEntry{exp: now.Add(c.ttl), data: val}
}

// redisCache fronts a shared Redis L2 with the in-process memCache as an L1.
// Every Redis call fails open: any error degrades to an L1 miss / no-store, so
// a Redis outage falls back to direct backend calls rather than an error.
type redisCache struct {
	rdb    *redis.Client
	l1     *memCache
	prefix string
	ttl    time.Duration
}

func newRedisCache(cfg *Config, l1 *memCache) (*redisCache, error) {
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, err
	}
	// Match the original Python implementation's 1s connect/read budget so a slow Redis never
	// stalls a /check past the backend timeout.
	opt.DialTimeout = time.Second
	opt.ReadTimeout = time.Second
	opt.WriteTimeout = time.Second
	return &redisCache{
		rdb:    redis.NewClient(opt),
		l1:     l1,
		prefix: cfg.RedisPrefix,
		ttl:    cfg.CacheTTL,
	}, nil
}

func (c *redisCache) Get(key string) ([]byte, bool) {
	if v, ok := c.l1.Get(key); ok {
		return v, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	v, err := c.rdb.Get(ctx, c.prefix+key).Bytes()
	if err != nil {
		return nil, false // miss or any Redis error -> fail open
	}
	c.l1.Put(key, v)
	return v, true
}

func (c *redisCache) Put(key string, val []byte) {
	c.l1.Put(key, val)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.rdb.Set(ctx, c.prefix+key, val, c.ttl).Err() // best effort
}
