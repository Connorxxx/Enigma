package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// 生成私钥
func GeneratePrivateKey() ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	block := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	return pem.EncodeToMemory(&block), nil
}

// 生成公钥
func GeneratePublicKey(privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey := &privKey.PublicKey
	derPubKey, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	pemPubKey := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPubKey,
	}
	publicKey := pem.EncodeToMemory(&pemPubKey)
	return publicKey, nil
}

// 使用公钥加密消息
func EncryptWithECC(publicKey []byte, message string) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to cast public key to ECDSA public key")
	}
	ciphertext, err := ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(ecPubKey), []byte(message), nil, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// 使用私钥解密消息
func DecryptByECC(privateKey []byte, ciphertext []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	plaintext, err := ecies.ImportECDSA(privKey).Decrypt(ciphertext, nil, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
