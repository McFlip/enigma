package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatal("Usage: getKey inP12 inPW outPW outDir")
	}
	inP12 := os.Args[1]
	inPW := os.Args[2]
	// outPW := os.Args[3]
	// outDir := os.Args[4]

	p12Bs, err := os.ReadFile(inP12)
	if err != nil {
		log.Fatal("Can't open p12 file")
	}
	key, cert, err := pkcs12.Decode(p12Bs, inPW)
	if err != nil {
		log.Fatal("Can't decode p12")
	}
	// fmt.Println(key)
	err = key.(*rsa.PrivateKey).Validate()
	if err != nil {
		log.Fatal("Key invalid")
	}
	serial := fmt.Sprintf("%x", cert.SerialNumber)
	fmt.Println(serial)
}
