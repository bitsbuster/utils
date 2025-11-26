package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/bitsbuster/utils/v2/log"
)

type Example struct {
	A         string   `json:"a"`
	B         uint64   `json:"b"`
	C         *big.Int `json:"c"`
	Signature string   `json:"signature"`
}

func TestRsaSignature(t *testing.T) {

	pk := getPrivateKey()

	if pk == nil {
		t.Error("Error getting private key")
		return
	}

	a := Example{
		A: "Lorem ipsumLorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
		B: uint64(9876),
		C: big.NewInt(65335),
	}

	signature, err := SignRsaMessage(a, pk)
	if err != nil {
		t.Errorf("Error signing message %+v", err)
	}

	a.Signature = b64.StdEncoding.EncodeToString(*signature)

	fmt.Printf("%+v", a)

}

func TestRsaSignatureVerification(t *testing.T) {

	w := Example{
		A:         "Lorem ipsumLorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
		B:         uint64(9876),
		C:         big.NewInt(65335),
		Signature: "wpkxfo5jiXiVj/OMEwtBnTU729lsgvYFktR+sUp6Vt/HZO2gNkyqYhz4rvJ+pFn/TmuK2StOKx6q/1EZO35hF7crxojorzUBlo2rVXK98m1E2NOCXwnEaPq3436VZLU85f3LlaR22Fgl7e2z0z777Xwl/DfFSASZs6lLmtqjOm9YtE+YLOYfj6xK4thaKmdFzdWUIlM3ounmkYh80eBHvBC+9D+RQccn9mnelhCO15DDDMkOfzSYwXeK4hHqFdQvihF2cmT+j0bI9AcuLowpxIz1y/wgSpjp470prABBR977SqVoBWsHxdL0tZ4luAfldpiPsPzjaZeUQSbA2lXNty1JI+CUd19OZTSzQaS22lyOj+YVTo8y0rgEOf0v/QzfqAburiPNXnKk42ifNEh/PMR4WGArN/TA55taHd+nIscUH/aK+RNvZcPfjknyxcOxnV1poqqLnPl6Bb/LtIyq6fwPTW3ZXD/odCanSlkvJ/FbtXzjdnRbNho9JgEMheeG0zDVg6qYQ03fKLPiDs+FQqAHBXEMbYfZKlCnrhJ9y7llPJgyPPJBUihElbL7sSI7LVEvRT4QXSvqC69iYNfQ9T/LFkWecUfZEKqk85rzSz3jdEPD10sM71n4gX0voHK8HO5ISRuDdzA/+6CtQIvpYYO0ygWWjKEj1YOh4TiYs0k=",
	}

	signature, _ := b64.StdEncoding.DecodeString(w.Signature)

	w.Signature = ""

	result := VerifyRsaMessage(w, getPublicKey(), signature)

	if !result {
		t.Errorf("Error Verifying message")

	}
}

func getPrivateKey() *rsa.PrivateKey {
	privatekey, err := os.ReadFile("/Users/alexlopez/dev/golang/ssl/jwt.rsa")

	if err != nil {
		return nil
	}

	privPem, _ := pem.Decode(privatekey)

	if privPem.Type != "RSA PRIVATE KEY" {
		fmt.Println("RSA private key is of the wrong type", privPem.Type)
		return nil
	}

	privPemBytes := privPem.Bytes

	var parsedKey interface{}
	//PKCS1
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		//If what you are sitting on is a PKCS#8 encoded key
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			log.Println(nil, "Unable to parse RSA private key, generating a temp one", err)
			return nil
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Println(nil, "Unable to parse RSA private key, generating a temp one", err)
		return nil
	}

	return privateKey
}

func getPublicKey() *rsa.PublicKey {
	pub, err := os.ReadFile("/Users/alexlopez/dev/golang/ssl/jwt.rsa.pub")
	if err != nil {
		log.Println(nil, "No RSA public key found, generating temp one")
		return nil
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		log.Println(nil, "Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public key - rsa public key not in pem format")
		return nil
	}
	fmt.Printf("%+v", pubPem.Type)
	if pubPem.Type != "RSA PUBLIC KEY" {
		log.Println(nil, "RSA public key is of the wrong type", pubPem.Type)
		return nil
	}
	var parsedKey interface{}
	var ok bool

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		log.Println(nil, "Unable to parse RSA public key, generating a temp one", err)
		return nil
	}

	var pubKey *rsa.PublicKey
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		log.Println(nil, "Unable to parse RSA public key, generating a temp one", err)
		return nil
	}

	return pubKey
}

func TestOtp(t *testing.T) {

	for i := 0; i < 20; i++ {
		otp, _ := GenerateOTP(6)
		fmt.Println(otp)
	}
}
