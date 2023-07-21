// Takes a dir of PSTs, a dir of PKCS8 keys, a password for the keys,
// and outputs dirs of *.msg files and an exceptions report.
// Output dir tree structure will mirror PST structure.
// PT emails in PSTs will be dropped.
package main

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/youmark/pkcs8"
)

type certKeyPair struct {
	cert    *x509.Certificate
	privKey crypto.PrivateKey
}

func main() {
	if len(os.Args) != 6 {
		fmt.Println("Usage: decipher inPstDir inKeyDir inPW outDir")
		fmt.Println("<inPstDir>: source directory of input PSTs containing encrypted email (Cypher Text)")
		fmt.Println(("<inCertDir>: source directory of encryption certs"))
		fmt.Println("<inKeyDir>: source directory of input PKCS8 keys")
		fmt.Println("<inPW>: the password you set as the outPW in getKeys")
		fmt.Println("<outDir>: Plain Text (PT) email msgs as well as exceptions report")
		os.Exit(1)
	}
	inPstDir := os.Args[1]
	inCertDir := os.Args[2]
	inKeyDir := os.Args[3]
	inPW := os.Args[4]
	outDir := os.Args[5]
	pstExceptions := []string{"PST File,Error"}
	msgExceptions := []string{"Target\tFrom\tTo\tCC\tBCC\tSubj\tDate\tMessage-Id\tAttachments\tError"}

	// get list of pst pstFiles to process
	pstFiles := []string{}
	err := filepath.Walk(inPstDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileExt := filepath.Ext(info.Name())
			if fileExt == ".pst" {
				pstFiles = append(pstFiles, path)
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if len(pstFiles) == 0 {
		log.Fatal("Error: input dir is empty")
	}

	// load keys
	certKeyPairs := []certKeyPair{}

	err = filepath.Walk(inCertDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			serial := strings.Split(filepath.Base(info.Name()), ".")[0]
			keyPath := filepath.Join(inKeyDir, serial+".key")
			certBytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			myCert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return err
			}
			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				return err
			}
			myKey, err := pkcs8.ParsePKCS8PrivateKey(keyBytes, []byte(inPW))
			if err != nil {
				return err
			}
			myCertKeyPair := certKeyPair{myCert, myKey}
			certKeyPairs = append(certKeyPairs, myCertKeyPair)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	// for _, ckPair := range certKeyPairs {
	// 	fmt.Println(ckPair.cert.PublicKeyAlgorithm)
	// 	fmt.Println(x509.MarshalPKIXPublicKey(&ckPair.privKey))
	// }

	// For each PST, Walk the B-Tree and handle each subtree as a goroutine

	for _, file := range pstFiles {
		err := processPST(file, outDir, certKeyPairs)
		if err != nil {
			pstException := fmt.Sprintf("%s,%s", file, err)
			pstExceptions = append(pstExceptions, pstException)
		}
	}

	// Write out exceptions
	fmt.Println(pstExceptions)
	fmt.Println(msgExceptions)
}
