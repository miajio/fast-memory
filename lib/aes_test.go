package lib_test

import (
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"

	"github.com/miajio/fast-memory/lib"
)

var (
	key = "userismiajioboss"
	val = "hello world test aes encryptor: 测试aes加密"
)

func TestECB(t *testing.T) {
	res, err := lib.AESEncryptor.ECB([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("ECB加密失败:%v", err)
	}
	resStr := hex.EncodeToString(res)
	fmt.Println("ECB加密后值:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.AESEncryptor.DECB([]byte(key), res)
	if err != nil {
		t.Fatalf("ECB解密失败:%v", err)
	}
	fmt.Println("ECB解密后值:", string(msg))
}

func TestCBC(t *testing.T) {
	res, err := lib.AESEncryptor.CBC([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("CBC加密失败:%v", err)
	}
	resStr := hex.EncodeToString(res)
	fmt.Println("CBC加密后值:", resStr)

	res, _ = hex.DecodeString(resStr)
	msgs, err := lib.AESEncryptor.DCBC([]byte(key), res)
	if err != nil {
		t.Fatalf("CBC解密失败:%v", err)
	}
	fmt.Println("CBC解密后值:", string(msgs))
}

func TestCRT(t *testing.T) {
	res, err := lib.AESEncryptor.CRT([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("CRT加密失败:%v", err)
	}

	resStr := hex.EncodeToString(res)
	fmt.Println("CRT加密后值:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.AESEncryptor.CRT([]byte(key), res)
	if err != nil {
		t.Fatalf("CRT解密失败:%v", err)
	}
	fmt.Println("CRT解密后值:", string(msg))
}

func TestCFB(t *testing.T) {
	res, err := lib.AESEncryptor.CFB([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("CFB加密失败:%v", err)
	}

	resStr := hex.EncodeToString(res)
	fmt.Println("CFB加密后值:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.AESEncryptor.DCFB([]byte(key), res)
	if err != nil {
		t.Fatalf("DCFB解密失败:%v", err)
	}
	fmt.Println("DCFB解密后值:", string(msg))
}

func TestOFB(t *testing.T) {
	res, err := lib.AESEncryptor.OFB([]byte(key), []byte(val))
	if err != nil {
		t.Fatalf("OFB加密失败:%v", err)
	}

	resStr := hex.EncodeToString(res)
	fmt.Println("OFB加密后值:", resStr)

	res, _ = hex.DecodeString(resStr)
	msg, err := lib.AESEncryptor.DOFB([]byte(key), res)
	if err != nil {
		t.Fatalf("DOFB解密失败:%v", err)
	}
	fmt.Println("DOFB解密后值:", string(msg))
}

func TestColor(t *testing.T) {
	res, _ := lib.AESEncryptor.CBC([]byte(key), []byte(val))
	msg := hex.EncodeToString(res)
	fmt.Println(msg)

	rgbs := lib.HexToColor(res)

	w := 10
	h := 0
	if len(rgbs)%10 == 0 {
		h = len(rgbs)%10 + 1
	} else {
		h = len(rgbs)/10 + 1
	}

	fmt.Println(h)
	imgFile, _ := os.Create("C:\\Users\\SnaroChrisXiao\\go\\src\\fast-memory\\temp\\out.png")
	defer imgFile.Close()

	img := image.NewNRGBA(image.Rect(0, 0, w, h))

	line := 0
	dex := 0

	fmt.Println(len(rgbs))
	for i := 0; i < len(rgbs); i++ {
		if i > 0 && i%10 == 0 {
			line++
			dex = 0
		}

		fmt.Println("RGB:", rgbs[i])

		r, g, b, err := lib.ColorToRGB(rgbs[i])
		if err != nil {
			t.Fatalf("color to rgb fail:%v", err)
		}
		fmt.Printf("RGB(%d, %d, %d)\n", r, g, b)
		img.Set(dex, line, color.RGBA{uint8(r), uint8(g), uint8(b), 255})
		dex++
	}
	err := png.Encode(imgFile, img)
	if err != nil {
		t.Fatalf("image encode fail: %v", err)
	}
}
