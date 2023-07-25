package core

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

// HexToColor
func HexToColor(val []byte) []string {
	v := hex.EncodeToString(val)
	l := len([]rune(v))

	v = fmt.Sprintf("%0*d", 6, 6-l%6) + v + fmt.Sprintf("%0*d", 6-l%6, 0)
	l = len([]rune(v))

	res := make([]string, 0)
	for i := 0; i < l/6; i++ {
		c := v[i*6 : i*6+6]
		res = append(res, c)
	}
	return res
}

// ColorToRGB
func ColorToRGB(color string) (r, g, b int, err error) {
	color64, err := strconv.ParseInt(color, 16, 32)
	if err != nil {
		return
	}
	color32 := int(color64)
	r = color32 >> 16
	g = (color32 & 0x00FF00) >> 8
	b = color32 & 0x0000FF
	return
}
