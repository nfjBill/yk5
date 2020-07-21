package utils

import (
	"github.com/nfjBill/yk5/utils/encrypt"
)

type IEcb struct {
	Encrypt func(string, ...string) string
	Decrypt func(string, ...string) string
}

type ICbc struct {
	Encrypt func(string, ...string) string
	Decrypt func(string, ...string) string
}

type ISymmetry struct {
	ECB    IEcb
	CBC    ICbc
	GetKey func(string) string
}

type IAsymmetry struct {
	Encrypt func(string, string) string
	Decrypt func(string, string) string
	KeyPair func() encrypt.IKeyPair
}

type IEncrypt struct {
	Abstract   func(string) string
	Symmetry   ISymmetry
	Asymmetric IAsymmetry
}

type ICipher struct {
	SM      IEncrypt
	General IEncrypt
	Mixin   IEncrypt
}

var Cipher = &ICipher{}

func init() {
	// 国密
	Cipher.SM.Asymmetric.Encrypt = encrypt.Sm2Encrypt
	Cipher.SM.Asymmetric.Decrypt = encrypt.Sm2Decrypt
	Cipher.SM.Asymmetric.KeyPair = encrypt.Sm2KeyPair
	Cipher.SM.Symmetry.ECB.Encrypt = encrypt.SM4EcbEncrypt
	Cipher.SM.Symmetry.ECB.Decrypt = encrypt.SM4EcbDecrypt
	Cipher.SM.Symmetry.CBC.Encrypt = encrypt.SM4CbcEncrypt
	Cipher.SM.Symmetry.CBC.Decrypt = encrypt.SM4CbcDecrypt
	Cipher.SM.Symmetry.GetKey = encrypt.Sm4GetKey
	Cipher.SM.Abstract = encrypt.Sm3

	// 国际
	Cipher.General.Asymmetric.Encrypt = encrypt.GRsaEncrypt
	Cipher.General.Asymmetric.Decrypt = encrypt.GRsaDecrypt
	Cipher.General.Asymmetric.KeyPair = encrypt.GKeyPair
	Cipher.General.Symmetry.ECB.Encrypt = encrypt.GAesEcbEncrypt
	Cipher.General.Symmetry.ECB.Decrypt = encrypt.GAesEcbDecrypt
	Cipher.General.Symmetry.CBC.Encrypt = encrypt.GAesCBCEncrypt
	Cipher.General.Symmetry.CBC.Decrypt = encrypt.GAesCBCDecrypt
	Cipher.General.Symmetry.GetKey = encrypt.Md5
	Cipher.General.Abstract = encrypt.Md5

	// 混合
	Cipher.Mixin.Asymmetric.Encrypt = encrypt.MAsymmetricEncrypt
	Cipher.Mixin.Asymmetric.Decrypt = encrypt.MAsymmetricDecrypt
	Cipher.Mixin.Asymmetric.KeyPair = encrypt.GKeyPair
	Cipher.Mixin.Symmetry.ECB.Encrypt = encrypt.SM4EcbEncrypt
	Cipher.Mixin.Symmetry.ECB.Decrypt = encrypt.SM4EcbDecrypt
	Cipher.Mixin.Symmetry.CBC.Encrypt = encrypt.SM4CbcEncrypt
	Cipher.Mixin.Symmetry.CBC.Decrypt = encrypt.SM4CbcDecrypt
	Cipher.Mixin.Symmetry.GetKey = encrypt.Sm4GetKey
	Cipher.Mixin.Abstract = encrypt.Sm3
}
