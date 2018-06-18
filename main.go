package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/thingful/zenroom-go"
)

type keyPair struct {
	PrivateKey string `json:"private"`
	PublicKey  string `json:"public"`
}

func main() {

	// Data to encrypt/decrypt
	data := []byte("secret data")

	// Generate Keys
	genKeysScript := []byte(`
		octet = require 'octet'
		ecdh = require 'ecdh'
		json = require 'json'

		keyring = ecdh.new('ec25519')
		keyring:keygen()
		
		output = json.encode({
			public = keyring:public():base64(),
			private = keyring:private():base64()
		})

		print(output)
	`)
	usrKeys, err := zenroom.Exec(genKeysScript, nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	devKeys, err := zenroom.Exec(genKeysScript, nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("User Keys: %s", usrKeys)
	log.Printf("Device Keys: %s", devKeys)

	userKeys := keyPair{}
	deviceKeys := keyPair{}

	err = json.Unmarshal(usrKeys, &userKeys)
	if err != nil {
		log.Panic(err)
	}
	err = json.Unmarshal(devKeys, &deviceKeys)
	if err != nil {
		log.Panic(err)
	}

	// Encrypt data
	encryptScript := []byte(`
			octet = require 'octet'
			ecdh = require 'ecdh'
			json = require 'json'

			msg = octet.new(#DATA)
			msg:string(DATA)

			keys = json.decode(KEYS)
			keyring = ecdh.new('ec25519')

			public = octet.new()
			public:base64(keys.public)

			private = octet.new()
			private:base64(keys.private)
			keyring:public(public)
			keyring:private(private)

			sess = keyring:session(public)
			zmsg = keyring:encrypt(sess, msg):base64()
			print(zmsg)
		`)
	encryptedMsg, err := zenroom.Exec(
		encryptScript,
		[]byte(fmt.Sprintf(`{"private": "%s", "public": "%s"}`, deviceKeys.PrivateKey, userKeys.PublicKey)),
		data)

	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Original Message: %s", data)
	log.Printf("Encrypted Message: %s", encryptedMsg)

	// Decrypt data
	decryptScript := []byte(`
			octet = require 'octet'
			ecdh = require 'ecdh'
			json = require 'json'

			zmsg = octet.new(#DATA)
			zmsg:base64(DATA)

			keys = json.decode(KEYS)

			keyring = ecdh.new('ec25519')

			public = octet.new()
			public:base64(keys.public)

			private = octet.new()
			private:base64(keys.private)

			keyring:public(public)
			keyring:private(private)

			sess = keyring:session(public)
			msg = keyring:decrypt(sess, zmsg)
			print(msg)
		`)
	decryptedMsg, err := zenroom.Exec(
		decryptScript,
		[]byte(fmt.Sprintf(`{"private": "%s", "public": "%s"}`, userKeys.PrivateKey, deviceKeys.PublicKey)),
		encryptedMsg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Decrypted Message:%s\n", decryptedMsg)

}
