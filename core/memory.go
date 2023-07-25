package core

// Cache default cache struct
type Cache struct {
	Id string // cache id: the id will be automatically generated based on the generator

	Hash string // cache hash
	Key  string // cache key
	Val  []byte // cache value
}

func (c *Cache) ToImg(path string) {
	//v := hex.EncodeToString(c.Val)

}
