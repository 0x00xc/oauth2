package oauth2

import (
	"errors"
	"github.com/cro4k/common/cache"
)

type lru struct {
	cache *cache.LRUCache
}

func (c *lru) Get(k string) (interface{}, error) {
	val, exist := c.cache.Get(k)
	if exist {
		return val, nil
	}
	return val, errors.New("not found")
}

func (c *lru) Put(k string, v interface{}) error {
	c.cache.Put(k, v)
	return nil
}

func (c *lru) Del(k string) error {
	c.cache.Del(k)
	return nil
}

func NewLRUStorage(max int) KVStorage {
	return cache.NewLRUCache(max)
}
