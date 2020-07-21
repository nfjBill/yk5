package encrypt

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/ZZMarquis/gm/sm2"
	"github.com/nfjBill/yk5/utils/goDash"
	"strings"
)

type IKeyPair struct {
	Pub string
	Pri string
}

func Sm2KeyPair() IKeyPair{
	pri, pub, err := sm2.GenerateKey(rand.Reader)
	goDash.ErrLog(err)

	privateKey := pri.GetRawBytes()
	publicKey := pub.GetRawBytes()

	var keyPair IKeyPair

	keyPair.Pri = strings.ToLower(hex.EncodeToString(privateKey))
	keyPair.Pub = "04" + strings.ToLower(hex.EncodeToString(publicKey))

	return keyPair
}

func Sm2Encrypt(data string, public string) string {
	if goDash.StrIsEmpty(public) {
		panic("public can't be empty")
	}

	public = strings.TrimPrefix(public, "04")

	publicKey, err := hex.DecodeString(public)
	goDash.ErrLog(err)

	pub, err := sm2.RawBytesToPublicKey(publicKey)
	goDash.ErrLog(err)

	src := []byte(data)
	cipherData, err := sm2.Encrypt(pub, src, sm2.C1C2C3)
	goDash.ErrLog(err)

	return strings.ToLower(hex.EncodeToString(cipherData))
}

func Sm2Decrypt(data string, private string) string {
	if goDash.StrIsEmpty(private) {
		panic("private can't be empty")
	}

	privateKey, err := hex.DecodeString(private)
	goDash.ErrLog(err)

	pri, err := sm2.RawBytesToPrivateKey(privateKey)
	goDash.ErrLog(err)

	src, err := hex.DecodeString(data)
	goDash.ErrLog(err)
	plainTxt, err := sm2.Decrypt(pri, src, sm2.C1C2C3)
	goDash.ErrLog(err)

	return string(plainTxt[:])
}