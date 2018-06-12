package main

import (
	"log"

	"github.com/thingful/zenroom-go"
)

func main() {

	// Data to encrypt/decrypt
	data := "my-data"

	// Generate Keys
	genKeysScript := `
	octet = require 'octet'
	ecdh = require 'ecdh'
	json = require 'json'

	keyring = ecdh.new('ec25519')
	keyring:keygen()
	
	output = json.encode({
		public = keyring:public():base64(),
		secret = keyring:private():base64()
	})

	print(output)
	`
	keys, err := zenroom.Exec(genKeysScript, "", "")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Keys:", keys)

	// Encrypt data
	encryptScript := `
	octet = require 'octet'
	ecdh = require 'ecdh'
	json = require 'json'

	msg = octet.new(#DATA)
	msg:string(DATA)

	keys = json.decode(KEYS)

	keyring = ecdh.new('ec25519')

	public = octet.new()
	public:base64(keys.public)

	secret = octet.new()
	secret:base64(keys.secret)

	keyring:public(public)
	keyring:private(secret)

	sess = keyring:session(public)
	zmsg = keyring:encrypt(sess, msg):base64()
	print(zmsg)
	`
	encryptedMsg, err := zenroom.Exec(encryptScript, keys, data)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Original Message:", data)
	log.Println("Encrypted Message:", encryptedMsg)

	// Decrypt data
	decryptScript := `
	octet = require 'octet'
	ecdh = require 'ecdh'
	json = require 'json'

	zmsg = octet.new(#DATA)
	zmsg:base64(DATA)

	keys = json.decode(KEYS)

	keyring = ecdh.new('ec25519')

	public = octet.new()
	public:base64(keys.public)

	secret = octet.new()
	secret:base64(keys.secret)

	keyring:public(public)
	keyring:private(secret)

	sess = keyring:session(public)
	msg = keyring:decrypt(sess, zmsg)
	print(msg)
	`
	decryptedMsg, err := zenroom.Exec(decryptScript, keys, encryptedMsg)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Decrypted Message:", decryptedMsg)
}
