package seshador

import "sync"

type KVSMemory struct {
	mutex  sync.Mutex
	values map[string]*SecretEntry
}

func NewKVSMemory() *KVSMemory {
	return &KVSMemory{
		mutex:  sync.Mutex{},
		values: map[string]*SecretEntry{},
	}
}

func (kvs *KVSMemory) Put(key []byte, value SecretEntry) error {
	kvs.mutex.Lock()
	defer kvs.mutex.Unlock()

	kvs.values[string(key)] = &value
	return nil
}

func (kvs *KVSMemory) Get(key []byte) (*SecretEntry, error) {
	kvs.mutex.Lock()
	defer kvs.mutex.Unlock()

	se := kvs.values[string(key)]
	return se, nil
}

func (kvs *KVSMemory) Delete(key []byte) error {
	kvs.mutex.Lock()
	defer kvs.mutex.Unlock()

	delete(kvs.values, string(key))
	return nil
}
