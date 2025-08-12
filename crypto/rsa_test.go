package crypto_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	utils "github.com/bitsbuster/utils/crypto"
)

func TestGenerateCryptoRSA(t *testing.T) {
	// utils.RsaGenerateAndStore(2048,"/tmp/id_jwt_test","/tmp/id_jwt_test.pub")

	c, err := utils.LoadPemFile("/tmp/id_jwt_test")
	if err != nil {
		t.Errorf("%+v", err)
		return
	}

	pkey, err := utils.RsaParsePrivateKeyFromPEM(c)
	if err != nil {
		t.Errorf("%+v", err)
		return
	}

	fmt.Printf("pkey.Size(): %v\n", pkey.Size())
	b, err := utils.LoadPemFile("/tmp/id_jwt_test.pub")
	if err != nil {
		t.Errorf("%+v", err)
		return
	}
	key, err := utils.RsaParsePublicKeyFromPEM(b)
	if err != nil {
		t.Errorf("%+v", err)
		return
	}

	fmt.Printf("key.Size(): %v\n", key.Size())

	m := "surprise surprise surprise surprise surprise surprise surprise surprise surprise surprise surprise surprise"

	encrypted, _ := utils.RsaEncryptWithPublicKey([]byte(m), key)
	fmt.Printf("hex.EncodeToString(encrypted): %v\n", hex.EncodeToString(encrypted))
	decrypted := utils.RsaDecryptWithPrivateKey(encrypted, pkey)

	fmt.Println(string(decrypted))
}
