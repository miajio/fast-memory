package core

// Cache default cache struct
type Cache struct {
	Id  string // cache id: the id will be automatically generated based on the generator
	Key string // cache key
	Val []byte // cache value
}
