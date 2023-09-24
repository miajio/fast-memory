package lib

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash/crc32"
)

// EncryptorImpl
type EncryptorImpl struct{}

// EncryptorInterface
type EncryptorInterface interface {
	MD5(val string) string    // val to md5
	Sha1(val string) string   // val to sha1
	Sha256(val string) string // val to sha256
	Sha512(val string) string // val to sha512

	CRC32(val string) uint32 // val to crc32

	Hmac(key, val string) string       // val to hmac
	HmacSha256(key, val string) string // val to hmac sha256
}

// Encryptor
var Encryptor EncryptorInterface = (*EncryptorImpl)(nil)

// MD5
func (*EncryptorImpl) MD5(val string) string {
	s := md5.New()
	s.Write([]byte(val))
	return hex.EncodeToString(s.Sum(nil))
}

// Sha1
func (*EncryptorImpl) Sha1(val string) string {
	s := sha1.New()
	s.Write([]byte(val))
	return hex.EncodeToString(s.Sum(nil))
}

// CRC32
func (*EncryptorImpl) CRC32(val string) uint32 {
	return crc32.ChecksumIEEE([]byte(val))
}

// Sha256
func (*EncryptorImpl) Sha256(val string) string {
	s := sha256.New()
	s.Write([]byte(val))
	return hex.EncodeToString(s.Sum(nil))
}

// Sha512
func (*EncryptorImpl) Sha512(val string) string {
	s := sha512.New()
	s.Write([]byte(val))
	return hex.EncodeToString(s.Sum(nil))
}

// Hmac
func (*EncryptorImpl) Hmac(key, val string) string {
	s := hmac.New(md5.New, []byte(key))
	s.Write([]byte(val))
	return hex.EncodeToString(s.Sum([]byte("")))
}

// HmacSha256
func (*EncryptorImpl) HmacSha256(key, val string) string {
	s := hmac.New(sha256.New, []byte(key))
	s.Write([]byte(val))
	return hex.EncodeToString(s.Sum([]byte("")))
}
