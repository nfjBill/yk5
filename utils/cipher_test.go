package utils

import (
	"fmt"
	"testing"
)

func TestSM(t *testing.T)  {
	getKey := Cipher.SM.Symmetry.GetKey("aAAbb")

	enc := Cipher.SM.Symmetry.ECB.Encrypt("中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文")
	dec := Cipher.SM.Symmetry.ECB.Decrypt(enc)

	cbcEnc := Cipher.SM.Symmetry.CBC.Encrypt("中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文")
	cbcDec := Cipher.SM.Symmetry.CBC.Decrypt(cbcEnc)

	sm3 := Cipher.SM.Abstract("中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文")

	keyPair := Cipher.SM.Asymmetric.KeyPair()

	sm2CipherData := Cipher.SM.Asymmetric.Encrypt("中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文", "04bd14935b1880eb4e59a5d0e29bfad82e8943ef3293cf23cbcd6580bba19c2c106e0d54af362eedca5a85a4e33ce23492a083a3e8a22981c2e5db0e9de49a188d")
	sm2PlainData := Cipher.SM.Asymmetric.Decrypt("04409e1d9df88e8288d5733367042bfe2ed3adfa07813dc6492eafa19abc9aa7f3689764f76c8059912a3f1d91d34932aacf2eab60928eb9032b4674a0ccba54bd6e90b39b522e3a5cfde6fa2336c276aed3d306ecc7a06208be6e5a20ffd27980ab1f8cfdf344974c4dd73fbcc168e815dd33d81788c5f624b7f6207f30dbb6ab8129ec24538f3602949ab294cd0fcec537d53d6f7c2f07378611ba9d960eab475652697ab575c9f53f22854265e8a91ab73eb6ed93eb5f674e26e165014c316dcd6743e2a476ed3250fb8ea957156ab929aa651a61ed48cd3841d543a8395511fdebe5ef0d2c798c5ff9b6af4d229ea5f451bed72ace4ebbeba9cb23", "ff4170970af520348c363ea9d36823f02c0683c32c897e0763bdbfc8ea51f004")

	fmt.Printf("sm2getKey：%+v\n", getKey)
	fmt.Printf("加密数据ecb：%v\n", enc)
	fmt.Printf("解密数据ecb：%v\n", dec)
	fmt.Printf("加密数据cbc：%v\n", cbcEnc)
	fmt.Printf("解密数据cbc：%v\n", cbcDec)
	fmt.Printf("摘要：%v\n", sm3)
	fmt.Printf("sm2秘钥对公匙：%+v\n", keyPair.Pub)
	fmt.Printf("sm2秘钥对私匙：%+v\n", keyPair.Pri)
	fmt.Printf("sm2加密数据：%+v\n", sm2CipherData)
	fmt.Printf("sm2解密数据：%+v\n", sm2PlainData)
}

func TestG(t *testing.T) {
	cipherG := Cipher.General
	gKeyPair := cipherG.Asymmetric.KeyPair()
	fmt.Printf("General公匙：%v\n", gKeyPair.Pub)
	fmt.Printf("General私匙：%v\n", gKeyPair.Pri)

	gRsaEnc := cipherG.Asymmetric.Encrypt("aaa", gKeyPair.Pub)
	fmt.Printf("GeneralRsaEnc：%v\n", gRsaEnc)

	gRsaDec := cipherG.Asymmetric.Decrypt(gRsaEnc, gKeyPair.Pri)
	fmt.Printf("GeneralRsaEDec：%v\n", gRsaDec)

	vc := "中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文中文"
	gKey := cipherG.Symmetry.GetKey(vc)
	fmt.Printf("GeneralKey：%v\n", gKey)

	gEcbEnc := cipherG.Symmetry.ECB.Encrypt(vc, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	fmt.Printf("GeneralEcbEnc：%v\n", gEcbEnc)

	gEcbDec := cipherG.Symmetry.ECB.Decrypt(gEcbEnc, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	fmt.Printf("GeneralEcbEDec：%v\n", gEcbDec)

	gCbcEnc := cipherG.Symmetry.CBC.Encrypt(vc, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa")
	fmt.Printf("GeneralCbcEnc：%v\n", gCbcEnc)

	gCbcDec := cipherG.Symmetry.CBC.Decrypt(gCbcEnc, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa")
	fmt.Printf("GeneralCbcEDec：%v\n", gCbcDec)
}

func TestGRsa(t *testing.T) {
	pub := `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyWF8zj8c8B1zZINcP+Es4CmKhdNepxF1b0zYbsNte2yBmbA64rnP
dx9WYShdA0Ep/5C8EAeuRhYrdG/SxhN+co6y8U2fpblc/eYXFWciwEVk9EPMx8By
yk9DStLwv/Jt2/RErgbTTEPLvJGF8GAvcaJ+yCnivFvSuq0TTTg83Y7whqECKdop
wqrNbeN6KrrATMEKnxnbF16eBtQrUQvzmrr9nKJuA1k9Wp88PCYtMYUjLnR1Rsyz
jruZ5JSLRNMrPvWEgsLH8LFakugr0ypSiDlF4eUZCC9G4zrxtgtHwOh1ohiAWuG7
lm45bil+OF2YTDDEHerBTvvopMcYMs7eoQIDAQAB
-----END RSA PUBLIC KEY-----`
	pri := `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyWF8zj8c8B1zZINcP+Es4CmKhdNepxF1b0zYbsNte2yBmbA6
4rnPdx9WYShdA0Ep/5C8EAeuRhYrdG/SxhN+co6y8U2fpblc/eYXFWciwEVk9EPM
x8Byyk9DStLwv/Jt2/RErgbTTEPLvJGF8GAvcaJ+yCnivFvSuq0TTTg83Y7whqEC
KdopwqrNbeN6KrrATMEKnxnbF16eBtQrUQvzmrr9nKJuA1k9Wp88PCYtMYUjLnR1
RsyzjruZ5JSLRNMrPvWEgsLH8LFakugr0ypSiDlF4eUZCC9G4zrxtgtHwOh1ohiA
WuG7lm45bil+OF2YTDDEHerBTvvopMcYMs7eoQIDAQABAoIBAF9v/yjzijBVlMFW
69ouSgk2RrrjkGEXChOkVJIxteofY1BFz7Jxotvukw5ahbIsKM5AdpAWQ8ZdbVyy
Pi63QF7kN/PZ+MYeke6WI+x1w2dhu9VzaFJmZ0BvzhFg5M3jA6ORIRdkjrD/FEga
o2JnAzUUcIdGKnlf/v+PVK1s8JOC+QRRkl3uKLCIK2M8M+yKr2qAYWxHS6lIuTBM
AAYQjeOFhA4IjAIT9Q7lhf60zdQzxHTWCjj39CQ74JYo1zNK5PiXbXr4VdwGy3Lu
/yDdqghf8yPx3XUuG4q2EG5Xhl4E1v9eB+gaMosVwn6NbXn2Fw9+gpWan1cx0neY
kGgHM/0CgYEA/U3cePtqPjGmDAHZtnkEWTbAPqp2kJ6iATLg4RX3GF2PyPVswf8X
hLy7gqMUAXisiQmfNlJMbBKrpTHtee5VFB3W6i+2iS76pdS8+b/YXBhSV5w43ZqG
8hvTq5G9/gBCCEJiUihMhXOzDWtFFMwamXAFiDiiBauaJhPr2JdWkbMCgYEAy4Yo
pn7SHWCx1oCwTOQCvnIDstomMEfjpyF35iBnhQPKTbSZOzTQFzMBf1KK6LHq5ywS
7m9rD/y1jhA/4OE8VrceiUrZIrR0XhF4hE+QvuQzwPK86VFCBVUG9exzsRUuphzZ
Z/eh7JQPs3KNZ7BUsRagmtJ5KmaZ6wpsSiDAnFsCgYEAuL/pZnQ5cVNVALz4xhZO
DaPZY9uAzspk7urlCkazCppzHOekg3pC9RWSzh2Tod8aOHlEHqK4CrszZjGcO6qR
czKwZe6W/Ee/mOQpUR+T9tfmdvACqd7jPgL9x81s/a3Ce7Ovcqzh4xQYLFlo8VpM
rE0AO/LSecBHli5BfqAjC/ECgYEAu8xCjEdvqG4GC1FZ3Ml0grkAErPbEyfyt9BZ
K37xJrr1nLgtwIUeEpodIphO1yL9B20S1vL2jpz4BmuWFfKf08BLLBJlw/FRg0+J
rkUg4hP+cWdKy9wQGI15y8jwhBFwpxTtw1KsFnoU9teYBXqe231umw3lgiuEkW5f
uBL6yAsCgYEArsWe8x1icVbrm8GaR32FDVvO1PGrhqjJ2HbtliZ0jfKGSh1pDHpe
KTKs84kOcT1jHwwQQTXHeiDqR7qW1+Tw9YiV8MWBBdVxBS0xY4d6rA35p84iMXxx
eeii6cascngnh3ZCxBMbGKH5nurcTicIQbwGzHk+bNa1bkzZtY14/KQ=
-----END RSA PRIVATE KEY-----`

	encTxt := "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"

	enc := Cipher.General.Asymmetric.Encrypt("aabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabbaabb", pub)
	dec := Cipher.General.Asymmetric.Decrypt(enc, pri)
	decc := Cipher.General.Asymmetric.Decrypt(encTxt, pri)

	fmt.Printf("加密:%v\n", enc)
	fmt.Printf("解密:%v\n", dec)
	fmt.Printf("解密Node密文:%v\n", decc)
}