package main

import (
	"log"

	"github.com/thingful/zenroom-go"
)

func main() {
	res, err := zenroom.Exec("print (1)", "", "")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(res)
}
