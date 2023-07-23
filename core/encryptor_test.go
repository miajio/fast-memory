package core_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/miajio/fast-memory/core"
)

func TestAES(t *testing.T) {
	key := "userismiajioboss"
	val := "hello world test aes encryptor: 测试aes加密"

	res := core.AESEncryptor.ECB([]byte(key), []byte(val))

	fmt.Printf("ECB加密后值: %x\n", res)

	msg := core.AESEncryptor.DECB([]byte(key), res)
	fmt.Println("ECB解密后值:", string(msg))

	ress, err := core.AESEncryptor.CBC(key, val)
	if err != nil {
		t.Fatalf("CBC加密失败:%v", err)
	}
	fmt.Println("CBC加密后值:", ress)

	msgs, err := core.AESEncryptor.DCBC(key, ress)
	if err != nil {
		t.Fatalf("CBC加密失败:%v", err)
	}
	fmt.Println("CBC解密后值:", string(msgs))

	res, err = core.AESEncryptor.CRT([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("CRT加密失败:%v", err)
	}
	fmt.Printf("CRT加密后值: %x\n", res)
	tval := fmt.Sprintf("%x", res)
	res, _ = hex.DecodeString(tval)
	msg, err = core.AESEncryptor.CRT([]byte(key), res)
	if err != nil {
		t.Fatalf("CRT解密失败:%v", err)
	}
	fmt.Println("CRT解密后值:", string(msg))

	res, err = core.AESEncryptor.CFB([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("CFB加密失败:%v", err)
	}
	fmt.Printf("CFB加密后值: %x\n", res)
	msg, err = core.AESEncryptor.DCFB([]byte(key), res)
	if err != nil {
		t.Fatalf("DCFB解密失败:%v", err)
	}
	fmt.Println("DCFB解密后值:", string(msg))

	res, err = core.AESEncryptor.OFB([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("OFB加密失败:%v", err)
	}
	fmt.Printf("OFB加密后值: %x\n", res)
	msg, err = core.AESEncryptor.DOFB([]byte(key), res)
	if err != nil {
		t.Fatalf("DOFB解密失败:%v", err)
	}
	fmt.Println("DOFB解密后值:", string(msg))
}
