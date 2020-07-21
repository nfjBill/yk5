package encrypt

func MAsymmetricEncrypt(data string, public string) string {
	gData := GRsaEncrypt(data, public)
	sData := SM4EcbEncrypt(gData)

	return sData
}

func MAsymmetricDecrypt(encData string, private string) string {
	sData := SM4EcbDecrypt(encData)
	gData := GRsaDecrypt(sData, private)

	return gData
}