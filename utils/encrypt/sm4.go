package encrypt

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/nfjBill/yk5/utils/goDash"
	"github.com/tjfoc/gmsm/sm4"
	"strings"
)

const (
	smSecretKeyDef string = "F26754EF50757CAE37080608DE644527"
	smIvKeyDef string = "8564C8F46CF481FF19F2F3A4F3A880BD"
)

// pkcs5填充
func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return nil
	}
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// ===
func ecbEnc(key, plainText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData := pkcs5Padding(plainText, blockSize)
	//origData, _ := pkcs7.Pad(plainText, 16)
	blockMode := ecb.NewECBEncrypter(block)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func ecbDec(key, cipherText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := ecb.NewECBDecrypter(block)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	//origData, _ = pkcs7.Unpad(origData, 16)
	return origData, nil
}

func cbcEnc(key, iv, plainText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData := pkcs5Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func cbcDec(key, iv, cipherText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

// public
func SM4EcbEncrypt(data string, keys ...string) string {
	secretKey := smSecretKeyDef
	if len(keys) > 0 {
		secretKey = keys[0]
	}
	// 128比特密钥
	//key := []byte(secretKey)
	key, err := hex.DecodeString(secretKey)
	goDash.ErrLog(err)
	dataByte := []byte(data)
	cipherTxt, err := ecbEnc(key, dataByte)
	goDash.ErrLog(err)

	return strings.ToUpper(hex.EncodeToString(cipherTxt))
}

func SM4EcbDecrypt(encData string, keys ...string) string {
	secretKey := smSecretKeyDef
	if len(keys) > 0 {
		secretKey = keys[0]
	}

	key, err := hex.DecodeString(secretKey)
	goDash.ErrLog(err)
	dataByte, err := hex.DecodeString(encData)
	goDash.ErrLog(err)
	plainTxt, err := ecbDec(key, dataByte)
	goDash.ErrLog(err)

	return string(plainTxt[:])
}

func SM4CbcEncrypt(data string, keys ...string) string {
	secretKey := smSecretKeyDef
	if len(keys) > 0 {
		secretKey = keys[0]
	}
	ivKey := smIvKeyDef
	if len(keys) > 1 {
		ivKey = keys[1]
	}
	key, err := hex.DecodeString(secretKey)
	goDash.ErrLog(err)
	iv, err := hex.DecodeString(ivKey)
	goDash.ErrLog(err)
	dataByte := []byte(data)
	cipherTxt, err := cbcEnc(key, iv, dataByte)
	goDash.ErrLog(err)

	return strings.ToUpper(hex.EncodeToString(cipherTxt))
}

func SM4CbcDecrypt(encData string, keys ...string) string {
	secretKey := smSecretKeyDef
	if len(keys) > 0 {
		secretKey = keys[0]
	}
	ivKey := smIvKeyDef
	if len(keys) > 1 {
		ivKey = keys[1]
	}
	key, err := hex.DecodeString(secretKey)
	goDash.ErrLog(err)
	iv, err := hex.DecodeString(ivKey)
	goDash.ErrLog(err)
	dataByte, err := hex.DecodeString(encData)
	goDash.ErrLog(err)
	plainTxt, err := cbcDec(key, iv, dataByte)
	goDash.ErrLog(err)

	return string(plainTxt[:])
}

func Sm4GetKey(str string) string {
	str = strings.ToLower(str)
	md5Str := Md5(str)
	sm3Str := Sm3(md5Str)

	return sm3Str[6:38]
}
