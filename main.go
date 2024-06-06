package main

import (
	"log"
)

func main() {
	mozApp := newMozApp()
	err := mozApp.InitUser()

	if err != nil {
		log.Fatalf("Unable to get user err:%s\n", err)
	}

	err = mozApp.CheckDevice()

	if err != nil {
		log.Fatalf("Unable to register device err:%s\n", err)
	}

	err = mozApp.InitUi()

	if err != nil {
		log.Fatalf("Unable to init UI err:%s\n", err)
	}
}
