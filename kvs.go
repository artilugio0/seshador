package seshador

type KeyValueStore interface {
	Put(key []byte, value SecretEntry) error
	Get(key []byte) (*SecretEntry, error)
	Delete(key []byte) error
}
