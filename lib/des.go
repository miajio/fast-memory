package lib

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"errors"
	"io"
)

// DESEncryptorImpl
type DESEncryptorImpl struct{}

// DESEncryptorInterface
type DESEncryptorInterface interface {
	ECB(key, val []byte) ([]byte, error)  // des encrypt electronic codebook book (ECB)
	DECB(key, val []byte) ([]byte, error) // des decrypt electronic codebook book (ECB)

	CBC(key, val []byte) ([]byte, error)  // des encrypt cipher block chaining (CBC)
	DCBC(key, val []byte) ([]byte, error) // des decrypt cipher block chaining (DCBC)

	CRT(key, val []byte) ([]byte, error) // des encrypt or decrypt counter (CTR)

	CFB(key, val []byte) ([]byte, error)  // des encrypt cipher feedback (CFB)
	DCFB(key, val []byte) ([]byte, error) // des decrypt cipher feedback (CFB)

	OFB(key, val []byte) ([]byte, error)  // des encrypt output FeedBack (OFB)
	DOFB(key, val []byte) ([]byte, error) // des decrypt output FeedBack (OFB)
}

// DESEncryptor
var DESEncryptor DESEncryptorInterface = (*DESEncryptorImpl)(nil)

// ECB
// des encrypt electronic codebook book
func (*DESEncryptorImpl) ECB(key, val []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	val = PKCS.Padding(val, bs)
	if len(val)%bs != 0 {
		return nil, errors.New("need a multiple of the blocksize")
	}
	res := make([]byte, len(val))
	dst := res
	for len(val) > 0 {
		block.Encrypt(dst, val[:bs])
		val = val[bs:]
		dst = dst[bs:]
	}
	return res, nil
}

// DECB
// des decrypt electronic codebook book
func (*DESEncryptorImpl) DECB(key, val []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(val)%bs != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	res := make([]byte, len(val))
	dst := res
	for len(val) > 0 {
		block.Decrypt(dst, val[:bs])
		val = val[bs:]
		dst = dst[bs:]
	}
	res = PKCS.UnPadding(res)
	return res, nil
}

// CBC
// des encrypt cipher block chaining (CBC)
func (*DESEncryptorImpl) CBC(key, val []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()

	val = PKCS.Padding(val, bs)
	md := cipher.NewCBCEncrypter(block, key[:bs])
	res := make([]byte, len(val))
	md.CryptBlocks(res, val)
	return res, nil
}

// DCBC
// des decrypt cipher block chaining (DCBC)
func (*DESEncryptorImpl) DCBC(key, val []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	bm := cipher.NewCBCDecrypter(block, key[:bs])
	res := make([]byte, len(val))
	bm.CryptBlocks(res, val)
	res = PKCS.UnPadding(res)
	return res, nil
}

// CRT
// des encrypt or decrypt counter
func (*DESEncryptorImpl) CRT(key []byte, val []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := bytes.Repeat([]byte("1"), block.BlockSize())
	stream := cipher.NewCTR(block, iv)

	dst := make([]byte, len(val))
	stream.XORKeyStream(dst, val)
	return dst, nil
}

// CFB
// des encrypt cipher feedback
func (*DESEncryptorImpl) CFB(key, val []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	res := make([]byte, des.BlockSize+len(val))
	iv := res[:des.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(res[des.BlockSize:], val)
	return res, nil
}

// DCFB
// des decrypt cipher feedback
func (*DESEncryptorImpl) DCFB(key, val []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(val) < des.BlockSize {
		return nil, errors.New("val length too short")
	}

	iv := val[:des.BlockSize]
	val = val[des.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(val, val)
	return val, nil
}

// OFB
// des encrypt output FeedBack
func (*DESEncryptorImpl) OFB(key, val []byte) ([]byte, error) {
	val = PKCS.Padding(val, des.BlockSize)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	res := make([]byte, des.BlockSize+len(val))
	iv := res[:des.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(res[des.BlockSize:], val)
	return res, nil
}

// DOFB
// des decrypt output FeedBack
func (*DESEncryptorImpl) DOFB(key, val []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := val[:des.BlockSize]
	val = val[des.BlockSize:]

	if len(val)%des.BlockSize != 0 {
		return nil, errors.New("val is not a multiple of the block size")
	}

	res := make([]byte, len(val))
	md := cipher.NewOFB(block, iv)
	md.XORKeyStream(res, val)
	res = PKCS.UnPadding(res)
	return res, nil
}
