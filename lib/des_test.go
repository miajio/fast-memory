package lib_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/miajio/fast-memory/lib"
)

func TestDESECB(t *testing.T) {
	key = "userismi"
	val = "hello world test aes encryptor: 测试aes加密"

	res, err := lib.DESEncryptor.ECB([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("ECB加密失败: %v", err)
	}
	resStr := hex.EncodeToString(res)
	fmt.Println("ECB加密成功:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.DESEncryptor.DECB([]byte(key), res)
	if err != nil {
		t.Fatalf("ECB解密失败: %v", err)
	}
	fmt.Println("ECB解密成功:", string(msg))
}

func TestDESCBC(t *testing.T) {
	key = "userismi"
	val = "hello world test aes encryptor: 测试aes加密"

	res, err := lib.DESEncryptor.CBC([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("CBC加密失败: %v", err)
	}
	resStr := hex.EncodeToString(res)
	fmt.Println("CBC加密成功:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.DESEncryptor.DCBC([]byte(key), res)
	if err != nil {
		t.Fatalf("CBC解密失败: %v", err)
	}
	fmt.Println("CBC解密成功:", string(msg))
}

func TestDESCRT(t *testing.T) {
	key = "userismi"
	val = "hello world test aes encryptor: 测试aes加密"

	res, err := lib.DESEncryptor.CRT([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("CRT加密失败:%v", err)
	}

	resStr := hex.EncodeToString(res)
	fmt.Println("CRT加密后值:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.DESEncryptor.CRT([]byte(key), res)
	if err != nil {
		t.Fatalf("CRT解密失败:%v", err)
	}
	fmt.Println("CRT解密后值:", string(msg))
}

func TestDESCFB(t *testing.T) {
	key = "userismi"
	val = "hello world test aes encryptor: 测试aes加密"

	res, err := lib.DESEncryptor.CFB([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("CFB加密失败:%v", err)
	}

	resStr := hex.EncodeToString(res)
	fmt.Println("CFB加密后值:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.DESEncryptor.DCFB([]byte(key), res)
	if err != nil {
		t.Fatalf("DCFB解密失败:%v", err)
	}
	fmt.Println("DCFB解密后值:", string(msg))
}

func TestDESOFB(t *testing.T) {
	key = "userismi"
	val = "hello world test aes encryptor: 测试aes加密"

	res, err := lib.DESEncryptor.OFB([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("OFB加密失败:%v", err)
	}

	resStr := hex.EncodeToString(res)
	fmt.Println("OFB加密后值:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.DESEncryptor.DOFB([]byte(key), res)
	if err != nil {
		t.Fatalf("DOFB解密失败:%v", err)
	}
	fmt.Println("DOFB解密后值:", string(msg))
}
