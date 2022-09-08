// Extract a private key from a p12 container and save to a PKCS8 file
// I use youmark's pkcs8 lib because the standard x509 lib
// doesn't allow for marshalling with a password.
// For security, we won't store private keys to disk in plain text.

package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	if len(os.Args) != 6 {
		log.Fatal("Usage: getKey inP12 inPW outPW outKeyDir outCertDir")
	}
	inP12 := os.Args[1]
	inPW := os.Args[2]
	outPW := os.Args[3]
	outKeyDir := os.Args[4]
	outCertDir := os.Args[5]

	p12Bs, err := os.ReadFile(inP12)
	if err != nil {
		log.Fatal("Can't open p12 file")
	}
	key, cert, err := pkcs12.Decode(p12Bs, inPW)
	if err != nil {
		log.Fatal("Can't decode p12")
	}
	err = key.(*rsa.PrivateKey).Validate()
	if err != nil {
		log.Fatal("Key invalid")
	}
	keyBs, err := pkcs8.ConvertPrivateKeyToPKCS8(key, []byte(outPW))
	if err != nil {
		log.Fatal("Can't convert key to PKCS8")
	}
	serial := fmt.Sprintf("%x", cert.SerialNumber)
	fmt.Println(serial)
	err = os.WriteFile(filepath.Join(outKeyDir, serial+".key"), keyBs, 0550)
	if err != nil {
		log.Fatal("Can't save key to outDir")
	}
	err = os.WriteFile(filepath.Join(outCertDir, serial+".cert"), cert.Raw, 0550)
	if err != nil {
		log.Fatal("Can't save cert to outDir")
	}
}
