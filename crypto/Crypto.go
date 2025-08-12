package crypto

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"

	"github.com/bitsbuster/utils/log"
	"golang.org/x/crypto/pbkdf2"
)

type EncryptResult struct {
	Salt                 []byte
	InitializationVector []byte
	Encrypted            []byte
}
type ECDSA struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

func DeriveKey(passphrase []byte, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 12)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passphrase), salt, 1000, 32, sha256.New), salt
}

// Encrypt encrypts plain text using passphrase.
// Returns an Hex String containing Salt, IV and ciphertext.
func Encrypt(passphrase, plaintext string) string {
	return EncryptBytes([]byte(passphrase), []byte(plaintext))
}

// Encrypt encrypts plain text using passphrase bytes.
// Returns an Hex String containing Salt, IV and ciphertext.
func EncryptBytes(passphrase, plaintext []byte) string {
	if e, err := EncryptRaw(passphrase, plaintext, nil, nil); err != nil {
		return ""
	} else {
		return hex.EncodeToString(e.Salt) + hex.EncodeToString(e.InitializationVector) + hex.EncodeToString(e.Encrypted)
	}

}

// Encrypts the plain text using the passphrase and returns an EncryptResult struct containing the Salt, the Initialization Vector and the encrypted data.
// It is based on http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf, Section 8.2
func EncryptRaw(passphrase, plaintext []byte, salt []byte, iv []byte) (*EncryptResult, error) {
	key, salt := DeriveKey(passphrase, salt)
	if iv == nil {
		iv = make([]byte, 12)
		rand.Read(iv)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		log.Errorf(nil, "Error creating new cipher.Block using derived key. %+v", err)
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		log.Errorf(nil, "Error getting the GCM from the cipher.Block. %+v", err)
	}
	data := aesgcm.Seal(nil, iv, []byte(plaintext), nil)

	return &EncryptResult{salt, iv, data}, nil
}

// Decrypt decrypts ciphertext using the passphrase
func Decrypt(passphrase, ciphertext string) string {
	return string(DecryptToBytes(passphrase, ciphertext))
}

// Decrypt decrypts ciphertext using the passphrase. The output is a byte array
func DecryptToBytes(passphrase, ciphertext string) []byte {

	if len(ciphertext) < 50 {
		return []byte{}
	}

	salt, err := hex.DecodeString(ciphertext[0:24])
	if err != nil {
		log.Errorf(nil, "Error decoding salt: %+v", err)
	}
	iv, err := hex.DecodeString(ciphertext[24:48])
	if err != nil {
		log.Errorf(nil, "Error decoding iv: %+v", err)
	}
	data, err := hex.DecodeString(ciphertext[48:])
	if err != nil {
		log.Errorf(nil, "Error decoding ciphertext: %+v", err)
	}
	key, _ := DeriveKey([]byte(passphrase), salt)
	b, err := aes.NewCipher(key)
	if err != nil {
		log.Errorf(nil, "Error creating New Cipher: %+v", err)
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		log.Errorf(nil, "Error creating new gcm: %+v", err)
	}
	data, err = aesgcm.Open(nil, iv, data, nil)
	if err != nil {
		log.Errorf(nil, "Error executing final decoding: %+v", err)
	}
	return data
}

func DecryptRaw(passphrase, salt, initializationVector, ciphertext []byte) ([]byte, error) {

	key, _ := DeriveKey([]byte(passphrase), salt)
	b, err := aes.NewCipher(key)
	if err != nil {
		log.Errorf(nil, "Error creating new cipher.Block using derived key. %+v", err)
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		log.Errorf(nil, "Error getting the GCM from the cipher.Block. %+v", err)
		return nil, err
	}
	data, err := aesgcm.Open(nil, initializationVector, ciphertext, nil)
	if err != nil {
		log.Errorf(nil, "Error decrypting and authenticating ciphertext. %+v", err)
		return nil, err
	}

	return data, nil
}

// Signs a message (for example an struct) with the given RSA private key
//
//	Input:
//	  The message to sign, it must be serializable to a JSON
//	  the RSA Privatekey to sign the message
//	Output:
//	  The signature as byte array
//	  the error if there is any error getting the Hash or the signature
func SignRsaMessage(m interface{}, privateKey *rsa.PrivateKey) (*[]byte, error) {

	hashed, err := GetDataHash(m)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])

	return &signature, err
}

// Verifies a message (for example an struct) signature using RSA public key
//
//	Input:
//	  The message to verify, it must be serializable to a JSON. Remember to remove the signature from message if you have included it in a field
//	  the RSA Public key to verify the message
//	  The signature as byte array
//	Output:
//	  true if the signature can be verified with the message or false elsewhere.
func VerifyRsaMessage(m interface{}, publicKey *rsa.PublicKey, signature []byte) bool {
	hashed, err := GetDataHash(m)
	if err != nil {
		return false
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, (*hashed)[:], signature)

	return err == nil
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// Loads a Pemfile using the file path from file system
func LoadPemFile(filePath string) ([]byte, error) {
	keyFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	// need to convert pemfile to []byte for decoding

	pemfileinfo, _ := keyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)

	// read pemfile content into pembytes
	buffer := bufio.NewReader(keyFile)
	_, err = buffer.Read(pembytes)
	return pembytes, err
}

// Decodes ECDSA Pem encoded public key
func (e *ECDSA) DecodeEcdsaPublicKeyPem(pemEncodedPub []byte) error {

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return err
	}

	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	e.PublicKey = publicKey
	return nil
}

// Decodes ECDSA Pem encoded private key
func (e *ECDSA) DecodeEcdsaPem(pemEncodedPriv []byte) error {
	block, _ := pem.Decode([]byte(pemEncodedPriv))
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return err
	}

	e.PrivateKey = privateKey
	e.PublicKey = &privateKey.PublicKey
	return nil
}

// Encodes Ecdsa private and public keys to PEM
func (e *ECDSA) EncodeEcdsaToPem() (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(e.PrivateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(&e.PrivateKey.PublicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

// Generates ECDSA pair and encodes them to pem
func (e *ECDSA) GenerateAndEncodeEcdsaKeys() (string, string, error) {
	var err error
	e.PrivateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	e.PublicKey = &e.PrivateKey.PublicKey

	privateKey, publicKey := e.EncodeEcdsaToPem()
	return privateKey, publicKey, nil
}

// Signs a message (for example an struct) with the given RSA private key
//
//	Input:
//	  The message to sign, it must be serializable to a JSON
//	  the RSA Privatekey to sign the message
//	Output:
//	  The signature as byte array
//	  the error if there is any error getting the Hash or the signature
func (e ECDSA) SignEcdsaMessage(m interface{}) (*[]byte, error) {

	hashed, err := GetDataHash(m)
	if err != nil {
		return nil, err
	}

	signature, err := ecdsa.SignASN1(rand.Reader, e.PrivateKey, hashed[:])

	return &signature, err
}

// Verifies a message (for example an struct) signature using RSA public key
//
//	Input:
//	  The message to verify, it must be serializable to a JSON. Remember to remove the signature from message if you have included it in a field
//	  the RSA Public key to verify the message
//	  The signature as byte array
//	Output:
//	  true if the signature can be verified with the message or false elsewhere.
func (e ECDSA) VerifyEcdsaMessage(m interface{}, signature []byte) bool {
	hashed, err := GetDataHash(m)
	if err != nil {
		return false
	}

	return ecdsa.VerifyASN1(e.PublicKey, (*hashed)[:], signature)
}

func GetDataHash(m interface{}) (*[32]byte, error) {
	message, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(message)
	return &hashed, nil
}

const otpChars = "1234567890"

// Generates OTP using secure random.
func GenerateOTP(length int) (string, error) {
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	otpCharsLength := len(otpChars)
	for i := 0; i < length; i++ {
		buffer[i] = otpChars[int(buffer[i])%otpCharsLength]
	}

	return string(buffer), nil
}
