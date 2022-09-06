// Takes a dir of PSTs, a dir of PKCS8 keys, a password for the keys,
// and outputs dirs of *.msg files and an exceptions report.
// Output dir tree structure will mirror PST structure.
// PT emails in PSTs will be dropped.
package main

import (
	"crypto/rsa"
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
	privKey *rsa.PrivateKey
}

func main() {
	if len(os.Args) != 6 {
		fmt.Println("Usage: decipher inPstDir inKeyDir inPW outDir")
		fmt.Println("<inPstDir>: source directory of input PSTs containing encrypted email (Cypher Text)")
		fmt.Println("<inCertDir>: source directory of recipient x509 certs")
		fmt.Println("<inKeyDir>: source directory of input PKCS8 private keys to match x509 certs")
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
	certKeyPairs := make([]certKeyPair, 0)

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
	err = filepath.WalkDir(inKeyDir, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() && filepath.Ext(d.Name()) == ".key" {
			keyBs, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// unmarshal key
			key, err := pkcs8.ParsePKCS8PrivateKeyRSA(keyBs, []byte(inPW))
			if err != nil {
				return err
			}
			// key was saved in the form "serial.key"
			serial := strings.Split(d.Name(), ".")[0]
			if err != nil {
				return err
			}
			certBs, err := os.ReadFile(filepath.Join(inCertDir, serial+".cert"))
			if err != nil {
				log.Fatal(err)
			}
			myCert, err := x509.ParseCertificate(certBs)
			if err != nil {
				log.Fatal(err)
			}
			myPair := certKeyPair{
				cert:    myCert,
				privKey: key,
			}
			certKeyPairs = append(certKeyPairs, myPair)
			return nil
		}
		return nil
	})
	if err != nil {
		log.Fatal("Failed to load keys")
	}

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
