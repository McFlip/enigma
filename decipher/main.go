// Takes a dir of eml files, a dir of PKCS8 keys, a password for the keys,
// and outputs dirs of *.eml files and an exceptions report.
// Output dir tree structure will mirror PST structure.
// PT emails will be dropped.
package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/youmark/pkcs8"
)

type certKeyPair struct {
	cert    *x509.Certificate
	privKey crypto.PrivateKey
}

type msgException struct {
	target, from, to, cc, bcc, subj, date, messageId, attachments, err string
}

func logMsgException(file string, msgBytes []byte, msgError error, errLog *[]string) error {
	msg, err := mail.ReadMessage(bytes.NewReader(msgBytes))
	if err != nil {
		return err
	}
	header := msg.Header
	target := file
	from := header.Get("From")
	to := header.Get("To")
	cc := header.Get("Cc")
	bcc := header.Get("Bcc")
	subj := header.Get("Subj")
	msgDate := header.Get("Date")
	msgId := header.Get("Message-ID")
	hasAttach := header.Get("X-MS-Has-Attach")
	var errStr string
	if msgError == nil {
		errStr = "success"
	} else {
		errStr = msgError.Error()
	}
	msgErr := msgException{
		target:      target,
		from:        from,
		to:          to,
		cc:          cc,
		bcc:         bcc,
		subj:        subj,
		date:        msgDate,
		messageId:   msgId,
		attachments: hasAttach,
		err:         errStr,
	}
	msgErrStr := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", msgErr.target, msgErr.from, msgErr.to, msgErr.cc, msgErr.bcc, msgErr.subj, msgErr.date, msgErr.messageId, msgErr.attachments, msgErr.err)
	*errLog = append(*errLog, msgErrStr)
	return nil
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
	corruptExceptions := []string{"PST File\tError\n"}
	decipherExceptions := []string{"Target\tFrom\tTo\tCC\tBCC\tSubj\tDate\tMessage-Id\tAttachments\tError\n"}
	decipherSuccess := []string{"Target\tFrom\tTo\tCC\tBCC\tSubj\tDate\tMessage-Id\tAttachments\tError\n"}
	ptExceptions := []string{"Target\tFrom\tTo\tCC\tBCC\tSubj\tDate\tMessage-Id\tAttachments\tError\n"}

	// get list of pst pstFiles to process
	pstFiles := []string{}
	err := filepath.Walk(inPstDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileExt := filepath.Ext(info.Name())
			if fileExt == ".eml" {
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

	fileNum := 1
	for _, file := range pstFiles {
		msgFile, err := os.ReadFile(file)
		if err != nil {
			corruptException := fmt.Sprintf("%s\t%s\n", file, err)
			corruptExceptions = append(corruptExceptions, corruptException)
			continue
		}
		foundCT := false
		pt, err := walkMultipart(msgFile, certKeyPairs, &foundCT)
		if err != nil {
			loggingErr := logMsgException(file, msgFile, err, &decipherExceptions)
			if loggingErr != nil {
				fmt.Printf("Error logging error for msg %s : %s\n", file, loggingErr)
				corruptException := fmt.Sprintf("%s\t%s\n", file, loggingErr)
				corruptExceptions = append(corruptExceptions, corruptException)
			}
			continue
		}
		if foundCT {
			fullPath := filepath.Join(outDir, fmt.Sprint(fileNum)+".eml")
			fileNum++
			err = os.WriteFile(fullPath, pt, 0666)
			if err != nil {
				fmt.Printf("Error writing out deciphered file %s : %s\n", file, err)
			}
			loggingErr := logMsgException(file, msgFile, nil, &decipherSuccess)
			if loggingErr != nil {
				fmt.Printf("Error logging success for %s : %s\n", file, loggingErr)
				corruptException := fmt.Sprintf("%s\t%s\n", file, loggingErr)
				corruptExceptions = append(corruptExceptions, corruptException)
			}
		} else {
			// either the input file was plaintext or corrupt and missing smime.p7m attachment
			loggingErr := logMsgException(file, msgFile, errors.New("plaintext input"), &ptExceptions)
			if loggingErr != nil {
				fmt.Printf("Error logging plaintext msg %s : %s\n", file, loggingErr)
				corruptException := fmt.Sprintf("%s\t%s\n", file, loggingErr)
				corruptExceptions = append(corruptExceptions, corruptException)
			}
		}
	}

	// Write out exceptions
	logs := map[string][]string{
		"corruptExceptions.csv":  corruptExceptions,
		"decipherExceptions.csv": decipherExceptions,
		"success.csv":            decipherSuccess,
		"ptExceptions.csv":       ptExceptions,
	}

	for logName, logSlc := range logs {
		logFile, err := os.OpenFile(logName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Can't open log file %s to write results", logName)
		}
		defer logFile.Close()
		for _, line := range logSlc {
			logFile.WriteString(line)
		}
	}
}
