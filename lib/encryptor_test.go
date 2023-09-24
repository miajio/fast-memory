package lib_test

import (
	"fmt"
	"testing"

	"github.com/miajio/fast-memory/lib"
)

func TestMd5(t *testing.T) {
	val := "123456"
	v := lib.Encryptor.MD5(val)
	fmt.Println("md5加密后值:", v)
}

func TestSha1(t *testing.T) {
	val := "123456"
	v := lib.Encryptor.Sha1(val)
	fmt.Println("sha1加密后值:", v)
}

func TestSha256(t *testing.T) {
	val := "123456"
	v := lib.Encryptor.Sha256(val)
	fmt.Println("sha256加密后值:", v)
}

func TestSha512(t *testing.T) {
	val := "123456"
	v := lib.Encryptor.Sha512(val)
	fmt.Println("sha512加密后值:", v)
}

func TestHmac(t *testing.T) {
	key := "user"
	val := "123456"
	v := lib.Encryptor.Hmac(key, val)
	fmt.Println("hmac加密后值:", v)
}

func TestHmacSha256(t *testing.T) {
	key := "user"
	val := "123456"
	v := lib.Encryptor.HmacSha256(key, val)
	fmt.Println("hmacsha256加密后值:", v)
}
