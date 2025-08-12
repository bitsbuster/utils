package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/bitsbuster/utils/errors"
	"github.com/bitsbuster/utils/log"
	"github.com/bitsbuster/utils/pointer"
)

var (
	ErrKeyMustBePEMEncoded = errors.New(errors.ErrorGeneratingRsa, "invalid Key: Key must be a PEM encoded PKCS1 or PKCS8 key")
	ErrNotRSAPrivateKey    = errors.New(errors.ErrorGeneratingRsa, "key is not a valid RSA private key")
	ErrNotRSAPublicKey     = errors.New(errors.ErrorGeneratingRsa, "key is not a valid RSA public key")
)

// RsaEncryptWithPublicKey encrypts data with public key
func RsaEncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		log.Errorf(nil, "An error was raised encrypting: %+v", err)
		return nil, err
	}
	return ciphertext, nil
}

// RsaDecryptWithPrivateKey decrypts data with private key
func RsaDecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		log.Printf(nil, "%+v", err)
	}
	return plaintext
}

// This shows an example of how to generate a SSH RSA Private/Public key pair and save it locally

func RsaGenerateAndStore(bitSize int, privateKeyFile, publicKeyFile string) (*rsa.PrivateKey, error) {

	privateKey, err := RsaGeneratePrivateKey(bitSize)
	if err != nil {
		log.Errorf(nil, "Error generating private {%d} bits key. %+v", bitSize, err)
		return nil, err
	}

	publicKeyBytes, err := RsaEncodePublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		log.Errorf(nil, "Error encoding public key to PEM: %+v", err)
		return nil, err
	}

	privateKeyBytes := RsaEncodePrivateKeyToPEM(privateKey)

	err = writeKeyToFile(privateKeyBytes, privateKeyFile)
	if err != nil {
		log.Errorf(nil, "Error writting private key to {%s} file. %+v", privateKeyFile, err)
		return nil, err
	}

	err = writeKeyToFile(publicKeyBytes, publicKeyFile)
	if err != nil {
		log.Errorf(nil, "Error writting public key to {%s} file. %+v", privateKeyFile, err)
		return nil, err
	}

	return privateKey, nil
}

// RsaGeneratePrivateKey creates a RSA Private Key of specified byte size
func RsaGeneratePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println(nil, "Private Key generated")
	return privateKey, nil
}

// RsaEncodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func RsaEncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// RsaEncodePublicKeyToPEM take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func RsaEncodePublicKeyToPEM(rsaPublicKey *rsa.PublicKey) ([]byte, error) {
	// Encode the public key as PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		log.Errorf(nil, "Failed to encode public key: %+v", err)
		return nil, err
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := os.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf(nil, "Key saved to: %s", saveFileTo)
	return nil
}

// Parse PEM encoded PKCS1 or PKCS8 private key
func RsaParsePrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func RsaParsePublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPublicKey
	}

	return pkey, nil
}

func RSACreatePairToPemFiles() (*string, *string, error) {
	// Generate a new RSA private key with 2048 bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Errorf(nil, "Error generating RSA private key: %+v", err)
		return nil, nil, errors.New(errors.ErrorGeneratingRsa, "Error generating RSA private key")
	}

	// Encode the private key to the PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBuffer := bytes.NewBufferString("")
	pem.Encode(privateKeyBuffer, privateKeyPEM)

	// Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	// Encode the public key to the PEM format
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	publicKeyBuffer := bytes.NewBufferString("")
	pem.Encode(publicKeyBuffer, publicKeyPEM)

	log.Traceln(nil, "RSA key pair generated successfully!")

	return pointer.String(privateKeyBuffer.String()), pointer.String(publicKeyBuffer.String()), nil
}
