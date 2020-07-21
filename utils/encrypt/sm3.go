package encrypt

import (
	"encoding/hex"
	"github.com/tjfoc/gmsm/sm3"
	"strings"
)

func Sm3(str string) string  {
	h := sm3.New()
	h.Write([]byte(str))
	sum := h.Sum(nil)

	return strings.ToUpper(hex.EncodeToString(sum))
}