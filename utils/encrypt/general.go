package encrypt

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"github.com/forgoer/openssl"
	"github.com/nfjBill/yk5/utils/goDash"
)

type IDigestLength struct {
	md4       int
	md5       int
	ripemd160 int
	rmd160    int
	sha1      int
	sha224    int
	sha256    int
	sha384    int
	sha512    int
}

const (
	gSecretKeyDef string = "08f8e0260c64418510c9cb2b06eee5cd"
	gIvKeyDef     string = "66c2abc64026a59a"
)

var digestLength = IDigestLength{
	md4:       16,
	md5:       16,
	ripemd160: 20,
	rmd160:    20,
	sha1:      20,
	sha224:    28,
	sha256:    32,
	sha384:    48,
	sha512:    64,
}

func Md5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func GAesEcbEncrypt(data string, keys ...string) string {
	secretKey := gSecretKeyDef
	if len(keys) == 1 {
		secretKey = keys[0]
	}

	key := []byte(secretKey)
	src := []byte(data)
	dst, err := openssl.AesECBEncrypt(src, key, openssl.PKCS7_PADDING)
	goDash.ErrLog(err)
	return base64.StdEncoding.EncodeToString(dst)
}

func GAesEcbDecrypt(encData string, keys ...string) string {
	secretKey := gSecretKeyDef
	if len(keys) == 1 {
		secretKey = keys[0]
	}

	key := []byte(secretKey)
	dst, err := base64.StdEncoding.DecodeString(encData)
	goDash.ErrLog(err)
	dst, _ = openssl.AesECBDecrypt(dst, key, openssl.PKCS7_PADDING)
	return string(dst)
}

func GAesCBCEncrypt(data string, keys ...string) string {
	secretKey := gSecretKeyDef
	if len(keys) > 0 {
		secretKey = keys[0]
	}
	ivKey := gIvKeyDef
	if len(keys) > 1 {
		ivKey = keys[1]
	}
	key := []byte(secretKey)
	iv := []byte(ivKey)
	src := []byte(data)
	dst, err := openssl.AesCBCEncrypt(src, key, iv, openssl.PKCS7_PADDING)
	goDash.ErrLog(err)
	return base64.StdEncoding.EncodeToString(dst)
}

func GAesCBCDecrypt(encData string, keys ...string) string {
	secretKey := gSecretKeyDef
	if len(keys) > 0 {
		secretKey = keys[0]
	}
	ivKey := gIvKeyDef
	if len(keys) > 1 {
		ivKey = keys[1]
	}
	key := []byte(secretKey)
	iv := []byte(ivKey)
	dst, err := base64.StdEncoding.DecodeString(encData)
	goDash.ErrLog(err)
	dst, err = openssl.AesCBCDecrypt(dst, key, iv, openssl.PKCS7_PADDING)
	return string(dst)
}

func GKeyPair() IKeyPair {
	var keyPair IKeyPair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	goDash.ErrLog(err)

	publicKey := &privateKey.PublicKey

	var priKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privateKey)
	priBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: priKeyBytes,
	}

	var priKeyBuffer []byte = pem.EncodeToMemory(priBlock)
	keyPair.Pri = string(priKeyBuffer)

	pubKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)

	pubBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	var pubKeyBuffer []byte = pem.EncodeToMemory(pubBlock)
	keyPair.Pub = string(pubKeyBuffer)

	return keyPair
}

func GRsaEncrypt(data string, public string) string {
	block, _ := pem.Decode([]byte(public))
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	goDash.ErrLog(err)
	partLen := publicKey.N.BitLen()/8 - digestLength.sha256 * 2 - 2 // pkcs1-oaep
	chunks := split([]byte(data), partLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		label := []byte("")
		cipherTxt, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, chunk, label)
		goDash.ErrLog(err)
		buffer.Write(cipherTxt)
	}

	decodedTxt := base64.StdEncoding.EncodeToString(buffer.Bytes())
	return decodedTxt
}

func GRsaDecrypt(encData string, private string) string {
	block, _ := pem.Decode([]byte(private))

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	goDash.ErrLog(err)

	decodedTxt, err := base64.StdEncoding.DecodeString(encData)
	goDash.ErrLog(err)

	partLen := privateKey.PublicKey.N.BitLen() / 8
	chunks := split([]byte(decodedTxt), partLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decryptedTxt, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, chunk, nil)
		goDash.ErrLog(err)
		buffer.Write(decryptedTxt)
	}

	return buffer.String()
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}
