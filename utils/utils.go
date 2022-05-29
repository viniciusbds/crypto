package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func GetPublicKey() *rsa.PublicKey {
	publicKeyPath := "certs/public.key"
	pubKeyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	publicKey, err := convertBytesToPublicKey(pubKeyBytes)
	if err != nil {
		fmt.Println(err)
	}
	return publicKey
}

func GetPrivateKey() *rsa.PrivateKey {
	privateKeyPath := "certs/private.key"
	privKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	privateKey, err := convertBytesToPrivateKey(privKeyBytes)
	if err != nil {
		fmt.Println(err)
	}
	return privateKey
}

func convertBytesToPublicKey(keyBytes []byte) (*rsa.PublicKey, error) {
	var err error

	block, _ := pem.Decode(keyBytes)
	blockBytes := block.Bytes

	publicKey, err := x509.ParsePKCS1PublicKey(blockBytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func convertBytesToPrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	var err error

	block, _ := pem.Decode(keyBytes)
	blockBytes := block.Bytes
	ok := x509.IsEncryptedPEMBlock(block)

	if ok {
		blockBytes, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(blockBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
