package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"

	"github.com/viniciusbds/crypto/utils"
)

// Definição do worker no Servidor principal (arrebol-pb)
type WorkerFromServer struct {
	ID      string  `json:"Id"`
	VCPU    float32 `json:"Vcpu"`
	RAM     uint32  `json:"Ram"`
	QueueID uint    `json:"QueueId"`
}

// Definição do worker no Worker (arrebol-pb-worker)
type WorkerFromWorker struct {
	Id      string
	Vcpu    float32
	Ram     uint32
	QueueId uint
	Token   string `json:"-"`
}

func main() {

	privateKey := utils.GetPrivateKey()
	publicKey := utils.GetPublicKey()

	// SENDER SIDE (WORKER)  - GENERATE SIGNATURE

	messageWorkerSide := &WorkerFromServer{ID: "worker-1", VCPU: 1, RAM: 2, QueueID: 1}
	msg1, err := json.Marshal(messageWorkerSide)
	check(err)
	msgHash1 := sha256.New()
	_, err = msgHash1.Write(msg1)
	if err != nil {
		log.Fatalln(err)
	}
	msgHashSum1 := msgHash1.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum1, nil)
	if err != nil {
		panic(err)
	}

	// RECEIVER SIDE (SERVER)  - VALIDATE SIGNATURE

	messageServerSide := &WorkerFromWorker{Id: "worker-1", Vcpu: 1, Ram: 2, QueueId: 1}
	msg2, err := json.Marshal(messageServerSide)
	check(err)

	msgHash2 := sha256.New()
	_, err = msgHash2.Write(msg2)
	if err != nil {
		log.Fatalln(err)
	}
	msgHashSum2 := msgHash2.Sum(nil)
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHashSum2, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return
	}

	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	fmt.Println("signature verified")
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
