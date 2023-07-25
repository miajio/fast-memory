package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type AESEncryptorImpl struct{}

type AESEncryptorInterface interface {
	ECB(key, val []byte) ([]byte, error)  // aes encrypt electronic codebook book (ECB)
	DECB(key, val []byte) ([]byte, error) // aes decrypt electronic codebook book (ECB)
	ECBGenerateKey(key []byte) []byte     // aes electronic codebook book generte key

	CBC(key, val []byte) ([]byte, error)  // aes encrypt cipher block chaining (CBC)
	DCBC(key, val []byte) ([]byte, error) // aes decrypt cipher block chaining (DCBC)

	CRT(key, val []byte) ([]byte, error) // aes encrypt or decrypt counter (CTR)

	CFB(key, val []byte) ([]byte, error)  // aes encrypt cipher feedback (CFB)
	DCFB(key, val []byte) ([]byte, error) // aes decrypt cipher feedback (CFB)

	OFB(key, val []byte) ([]byte, error)  // aes encrypt output FeedBack (OFB)
	DOFB(key, val []byte) ([]byte, error) // aes decrypt output FeedBack (OFB)

}

var AESEncryptor AESEncryptorInterface = (*AESEncryptorImpl)(nil)

// ECB
// aes encrypt electronic codebook book
func (*AESEncryptorImpl) ECB(key, val []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(AESEncryptor.ECBGenerateKey(key))
	if err != nil {
		return nil, err
	}
	l := (len(val) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, l*aes.BlockSize)
	copy(plain, val)
	pad := byte(len(plain) - len(val))
	for i := len(val); i < len(plain); i++ {
		plain[i] = pad
	}
	res := make([]byte, len(plain))
	for bs, be := 0, cipher.BlockSize(); bs <= len(val); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(res[bs:be], plain[bs:be])
	}
	return res, nil
}

// DECB
// aes decrypt electronic codebook book
func (*AESEncryptorImpl) DECB(key, val []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(AESEncryptor.ECBGenerateKey(key))
	if err != nil {
		return nil, err
	}
	res := make([]byte, len(val))
	for bs, be := 0, cipher.BlockSize(); bs < len(val); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(res[bs:be], val[bs:be])
	}
	trim := 0
	if len(res) > 0 {
		trim = len(res) - int(res[len(res)-1])
	}
	return res[:trim], nil
}

// ECBGenerateKey
// aes electronic codebook book generte key
func (*AESEncryptorImpl) ECBGenerateKey(key []byte) []byte {
	res := make([]byte, 16)
	copy(res, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			res[j] ^= key[i]
		}
	}
	return res
}

// CBC
// aes encrypt cipher block chaining
// the key length must be 16,24,32
func (*AESEncryptorImpl) CBC(key, val []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()

	val = PKCS.Padding(val, bs)
	bm := cipher.NewCBCEncrypter(block, key[:bs])

	res := make([]byte, len(val))
	bm.CryptBlocks(res, val)
	return res, nil
}

// DCBC
// aes decrypt cipher block chaining
// the key length must be 16,24,32
func (*AESEncryptorImpl) DCBC(key, val []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
// aes encrypt or decrypt counter
func (*AESEncryptorImpl) CRT(key []byte, val []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
// aes encrypt cipher feedback
func (*AESEncryptorImpl) CFB(key, val []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	res := make([]byte, aes.BlockSize+len(val))
	iv := res[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(res[aes.BlockSize:], val)
	return res, nil
}

// DCFB
// aes decrypt cipher feedback
func (*AESEncryptorImpl) DCFB(key, val []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(val) < aes.BlockSize {
		return nil, errors.New("val length too short")
	}

	iv := val[:aes.BlockSize]
	val = val[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(val, val)
	return val, nil
}

// OFB
// aes encrypt output FeedBack
func (*AESEncryptorImpl) OFB(key, val []byte) ([]byte, error) {
	val = PKCS.Padding(val, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	res := make([]byte, aes.BlockSize+len(val))
	iv := res[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(res[aes.BlockSize:], val)
	return res, nil
}

// DOFB
// aes decrypt output FeedBack
func (*AESEncryptorImpl) DOFB(key, val []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := val[:aes.BlockSize]
	val = val[aes.BlockSize:]

	if len(val)%aes.BlockSize != 0 {
		return nil, errors.New("val is not a multiple of the block size")
	}

	res := make([]byte, len(val))
	md := cipher.NewOFB(block, iv)
	md.XORKeyStream(res, val)
	res = PKCS.UnPadding(res)
	return res, nil
}
