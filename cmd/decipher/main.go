// Takes a dir of eml files, a dir of x509 certs, a dir of PKCS8 keys paired to the certs, and a password for the keys,
// and outputs dirs of *.eml files and an exceptions report.
// Output dir is a flat folder. Log will show original path from input.
// PT emails will be dropped but logged.
package decipher

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

func logMsgException(file string, msgBytes []byte, msgError error, errLog *os.File) error {
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
	subj := header.Get("Subject")
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
	msgErrStr := fmt.Sprintf(
		"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		msgErr.target,
		msgErr.from,
		msgErr.to,
		msgErr.cc,
		msgErr.bcc,
		msgErr.subj,
		msgErr.date,
		msgErr.messageId,
		msgErr.attachments,
		msgErr.err,
	)
	// print success to screen
	// if msgError == nil {
	// 	fmt.Println(msgErrStr)
	// }
	errLog.WriteString(msgErrStr)
	return nil
}

func Decipher(inPstDir, inCertDir, inKeyDir, inPW, outDir string) {
	// logs, if they already exist skip header and we append write
	// TODO: refactor log creation to a factory func
	var corruptLog, decipherExceptLog, successLog, ptExceptLog *os.File

	// logs corrupt input
	corruptPath := filepath.Join(outDir, "logs", "corruptExceptions.csv")
	if _, err := os.Stat(corruptPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			corruptLog, err = os.OpenFile(corruptPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				log.Fatalf("Can't open log file %s to write results", corruptPath)
			}
			corruptLog.WriteString("Eml File\tError\n")
		}
	} else {

		corruptLog, err = os.OpenFile(corruptPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Can't open log file %s to write results", corruptPath)
		}
	}
	defer corruptLog.Close()

	// logs exceptions from decipher func such as no key
	decipherExceptPath := filepath.Join(outDir, "logs", "decipherExceptions.csv")
	if _, err := os.Stat(decipherExceptPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			decipherExceptLog, err = os.OpenFile(
				decipherExceptPath,
				os.O_WRONLY|os.O_CREATE|os.O_APPEND,
				0644,
			)
			if err != nil {
				log.Fatalf("Can't open log file %s to write results", decipherExceptPath)
			}
			decipherExceptLog.WriteString(
				"Target\tFrom\tTo\tCC\tBCC\tSubj\tDate\tMessage-Id\tAttachments\tError\n",
			)
		}
	} else {
		decipherExceptLog, err = os.OpenFile(
			decipherExceptPath,
			os.O_WRONLY|os.O_CREATE|os.O_APPEND,
			0644,
		)
		if err != nil {
			log.Fatalf("Can't open log file %s to write results", decipherExceptPath)
		}
	}
	defer decipherExceptLog.Close()

	// logs successfuly deciphered plaintext
	successPath := filepath.Join(outDir, "logs", "success.csv")
	if _, err := os.Stat(successPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			successLog, err = os.OpenFile(successPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				log.Fatalf("Can't open log file %s to write results", successPath)
			}
			successLog.WriteString(
				"Target\tFrom\tTo\tCC\tBCC\tSubj\tDate\tMessage-Id\tAttachments\tError\n",
			)
		}
	} else {
		successLog, err = os.OpenFile(successPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Can't open log file %s to write results", successPath)
		}
	}
	defer successLog.Close()

	ptExceptPath := filepath.Join(outDir, "logs", "ptExceptions.csv")
	if _, err := os.Stat(ptExceptPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			ptExceptLog, err = os.OpenFile(ptExceptPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				log.Fatalf("Can't open log file %s to write results", ptExceptPath)
			}
			ptExceptLog.WriteString(
				"Target\tFrom\tTo\tCC\tBCC\tSubj\tDate\tMessage-Id\tAttachments\tError\n",
			)
		}
	} else {
		ptExceptLog, err = os.OpenFile(ptExceptPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Can't open log file %s to write results", ptExceptPath)
		}
	}
	defer ptExceptLog.Close()

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
			corruptLog.WriteString(corruptException)
			continue
		}
		foundCT := false
		pt, err := walkMultipart(msgFile, certKeyPairs, &foundCT)
		if err != nil {
			loggingErr := logMsgException(file, msgFile, err, decipherExceptLog)
			if loggingErr != nil {
				// fmt.Printf("Error logging error for msg %s : %s\n", file, loggingErr)
				corruptException := fmt.Sprintf("%s\t%s\n", file, loggingErr)
				corruptLog.WriteString(corruptException)
			}
			continue
		}
		if foundCT {
			// output files are auto numbered .eml files
			fullPath := filepath.Join(outDir, fmt.Sprint(fileNum)+".eml")
			for _, err := os.Stat(fullPath); err == nil; _, err = os.Stat(fullPath) {
				fileNum++
				fullPath = filepath.Join(outDir, fmt.Sprint(fileNum)+".eml")
			}
			fileNum++
			err = os.WriteFile(fullPath, pt, 0666)
			if err != nil {
				fmt.Printf("Error writing out deciphered file %s : %s\n", file, err)
			}
			loggingErr := logMsgException(file, msgFile, nil, successLog)
			if loggingErr != nil {
				// fmt.Printf("Error logging success for %s : %s\n", file, loggingErr)
				corruptException := fmt.Sprintf("%s\t%s\n", file, loggingErr)
				corruptLog.WriteString(corruptException)
			}
		} else {
			// either the input file was plaintext or corrupt and missing smime.p7m attachment
			loggingErr := logMsgException(file, msgFile, errors.New("plaintext input"), ptExceptLog)
			if loggingErr != nil {
				// fmt.Printf("Error logging plaintext msg %s : %s\n", file, loggingErr)
				corruptException := fmt.Sprintf("%s\t%s\n", file, loggingErr)
				corruptLog.WriteString(corruptException)
			}
		}
	}
}
