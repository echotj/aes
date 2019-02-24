package ctx

import (
	"encoding/hex"
	"utils"
	"strings"
	"encoding/xml"
	"crypto/md5"
	"fmt"
)

const (
	GIV =  "1234567891234567" //Set iv you want to use
)
func AES128CBCEnc_WithIV(plainText,secKey string)string{
	plainTextBytes := []byte(plainText)
	//todo 需要对secKey进行hex的Decode
	secKeyBytes,_ := hex.DecodeString(secKey)
	encText,_ := utils.Aes128Encrypt(plainTextBytes,secKeyBytes,[]byte(GIV))
	//todo 需要对结果进行hex进行Encode
	return hex.EncodeToString(encText)
}
func AES128CBCDec_WithIV(encStr,key string)[]byte{
	hexEncBytes,_ := hex.DecodeString(encStr)
	//hex编码key
	hexKeyBytes,_ := hex.DecodeString(key)
	dec,_ := utils.Aes128Decrypt(hexEncBytes,hexKeyBytes,[]byte(GIV))
	return dec
}
//XML格式化
func XmlFormat(confBytes []byte,formatData interface{}){
	conf_str := string(confBytes)
	old_encode := `encoding="GBK"`
	new_encode := `encoding="UTF-8"`
	sdmi_conf_str =  strings.Replace(conf_str,old_encode,new_encode,1)
	xml.Unmarshal([]byte(conf_str),&formatData)
}
func Sm_GetMD5(s string) string {
	strings.ToLower(s)
	m := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", m)
}
