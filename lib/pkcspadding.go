package lib

import "bytes"

type PKCSImpl struct{}

type PKCSInterface interface {
	Padding(val []byte, blockSize int) []byte // pkcs padding
	UnPadding(val []byte) []byte              // pkcs unpadding
}

var PKCS PKCSInterface = (*PKCSImpl)(nil)

// PKCS Padding
// pkcs padding
func (*PKCSImpl) Padding(val []byte, blockSize int) []byte {
	pd := blockSize - len(val)%blockSize
	pdt := bytes.Repeat([]byte{byte(pd)}, pd)
	return append(val, pdt...)
}

// PKCS UnPadding
// pkcs unpadding
func (*PKCSImpl) UnPadding(val []byte) []byte {
	l := len(val)
	upd := int(val[l-1])
	return val[:(l - upd)]
}
