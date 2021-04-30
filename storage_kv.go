package oauth2

import (
	"errors"
	"sync"
)

type KVStorage interface {
	Get(k string) (interface{}, error)
	Put(k string, v interface{}) error
	Del(k string) error
}

type SyncMap struct {
	syncMap *sync.Map
}

func (m *SyncMap) Get(k string) (interface{}, error) {
	v, ex := m.syncMap.Load(k)
	if ex {
		return v, nil
	}
	return v, errors.New("not found")
}

func (m *SyncMap) Put(k string, v interface{}) error {
	m.syncMap.Store(k, v)
	return nil
}

func (m *SyncMap) Del(k string) error {
	m.syncMap.Delete(k)
	return nil
}

func NewSyncMap() *SyncMap {
	return &SyncMap{syncMap: new(sync.Map)}
}
