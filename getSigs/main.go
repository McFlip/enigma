// Parse certificate info from signed emails. This info helps you fetch keys from escrow.
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	pst "github.com/mooijtech/go-pst/v4/pkg"
	pkcs7 "go.mozilla.org/pkcs7"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: .\\getSigs.exe <inputDir> <outputDir>")
		fmt.Println("<inputDir>: source directory of input PSTs containing signed emails sent by the custodians")
		fmt.Println("<outputDir>: the file 'allCerts.txt' will be output here. It will contain all available certs de-duplicated.")
		os.Exit(1)
	}
	inDir := os.Args[1]
	outDir := os.Args[2]

	// get list of pst files to process
	files := []string{}
	err := filepath.Walk(inDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileExt := filepath.Ext(info.Name())
			if fileExt == ".pst" {
				files = append(files, path)
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatal("Error: input dir is empty")
	}

	// process each pst in a goroutine
	// get cert back in channel
	// use a map to dedup with CA+serial as composite key
	c := make(chan string)
	allCerts := make(map[string]string)
	for _, file := range files {
		go processPST(file, c)
	}
	for completedFiles := 0; completedFiles < len(files); completedFiles++ {
		currMsg := <-c
		for currMsg != "---END---" {
			// composite key on serial # and CA strings
			serial, ca, found := "", "", false
			_, serial, found = strings.Cut(currMsg, "Serial: ")
			if !found {
				log.Printf("Error parsing cert: %s\n", currMsg)
				currMsg = <-c
				continue
			}
			serial, _, found = strings.Cut(serial, "\n")
			if !found {
				log.Printf("Error parsing cert: %s\n", currMsg)
				currMsg = <-c
				continue
			}
			_, ca, found = strings.Cut(currMsg, "Certificate Authority: ")
			if !found {
				log.Printf("Error parsing cert: %s\n", currMsg)
				currMsg = <-c
				continue
			}
			key := ca + serial
			allCerts[key] = "\n----------\n" + currMsg
			currMsg = <-c
		}
	}
	// write out the allCerts.txt file
	// fmt.Println(allCerts)
	allCertsStr := ""
	for _, val := range allCerts {
		allCertsStr = allCertsStr + val + "\n"
	}
	allCertsStr = allCertsStr + "----------\n\n"
	err = os.WriteFile(filepath.Join(outDir, "allCerts.txt"), []byte(allCertsStr), 0666)
	if err != nil {
		log.Fatal("failed to write output to allCerts.txt")
	}
}

// goroutine processes 1 pst
func processPST(file string, c chan string) {
	pstFile, err := pst.NewFromFile(file)

	if err != nil {
		fmt.Printf("Failed to create PST file: %s\n", err)
		c <- ""
		return
	}

	defer func() {
		err := pstFile.Close()

		if err != nil {
			fmt.Printf("Failed to close PST file: %s", err)
		}
	}()

	isValidSignature, err := pstFile.IsValidSignature()
	if err != nil {
		fmt.Printf("Failed to read signature: %s\n", err)
		c <- "---END---"
		return
	}
	if !isValidSignature {
		fmt.Printf("Invalid file signature.\n")
		c <- "---END---"
		return
	}

	formatType, err := pstFile.GetFormatType()
	if err != nil {
		fmt.Printf("Failed to get format type: %s\n", err)
		c <- "---END---"
		return
	}

	encryptionType, err := pstFile.GetEncryptionType(formatType)
	if err != nil {
		fmt.Printf("Failed to get encryption type: %s\n", err)
		c <- "---END---"
		return
	}

	err = pstFile.InitializeBTrees(formatType)
	if err != nil {
		fmt.Printf("Failed to initialize node and block b-tree.\n")
		c <- "---END---"
		return
	}

	rootFolder, err := pstFile.GetRootFolder(formatType, encryptionType)

	if err != nil {
		fmt.Printf("Failed to get root folder: %s\n", err)
		c <- "---END---"
		return
	}

	err = GetSubFolders(pstFile, rootFolder, formatType, encryptionType, c)

	if err != nil {
		fmt.Printf("Failed to get sub-folders: %s\n", err)
		c <- "---END---"
		return
	}
	c <- "---END---"
}

// Go Routine processes 1 message
func processMsg(msg pst.Message, pstFile pst.File, formatType string, encryptionType string, c chan string) {
	// we're only interested in the smime.p7m attachment
	hasAttachments, err := msg.HasAttachments()
	if err != nil {
		log.Println(err)
		c <- ""
	}
	if !hasAttachments {
		c <- ""
	}

	from, err := msg.GetFrom(&pstFile, formatType, encryptionType)
	if err != nil {
		log.Println(err)
		c <- ""
	}

	myAttachments, err := msg.GetAttachments(&pstFile, formatType, encryptionType)
	if err != nil {
		log.Println(err)
		c <- ""
	}

	for _, attachment := range myAttachments {
		// check MIME type
		mimeType, _ := attachment.GetString(14094)
		if mimeType != "multipart/signed" {
			continue
		}

		// Read the attachment
		attachStream, err := attachment.GetInputStream(&pstFile, formatType, encryptionType)
		if err != nil {
			log.Println(err)
			c <- ""
		}
		attachBytes, err := attachStream.ReadCompletely()
		if err != nil {
			log.Println(err)
			c <- ""
		}
		msg, err := mail.ReadMessage(bytes.NewReader(attachBytes))
		if err != nil {
			log.Println(err)
			c <- ""
		}

		// Iterate through msg parts until we get to the smime.p7s
		_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
		if err != nil {
			log.Println(err)
			c <- ""
		}
		mr := multipart.NewReader(msg.Body, params["boundary"])
		eof := false
		for !eof {
			p, err := mr.NextPart()
			if err == io.EOF {
				eof = true
				continue
			}
			if err != nil {
				log.Fatal(err)
			}
			slurp, err := io.ReadAll(p)
			if err != nil {
				log.Fatal(err)
			}
			if p.Header.Get("Content-Type") == "application/pkcs7-signature; name=\"smime.p7s\"" {
				// parse the pkcs7 struct
				dst := make([]byte, len(slurp))
				n, err := base64.StdEncoding.Decode(dst, slurp)
				if err != nil {
					log.Println(err)
					c <- ""
				}
				dst = dst[:n]
				p7m, err := pkcs7.Parse(dst)
				if err != nil {
					log.Println(err)
					c <- ""
				}

				// Get the signer info - this is the main objective!
				signer := p7m.GetOnlySigner()

				// Common Name is in the form LAST.FIRST.MIDDLE.EDIPI
				cn := signer.Subject.CommonName
				log.Println(cn)
				cnSplit := strings.Split(cn, ".")
				lName := cnSplit[0]
				fName := cnSplit[1]
				mName := ""
				edipi := cnSplit[len(cnSplit)-1]
				if len(cnSplit) == 4 {
					mName = cnSplit[2]
				}

				// get email address directly from the cert, if doesn't exist fall back to FROM field in email
				email := strings.Join(signer.EmailAddresses, ";")

				// Principle Name, if blank then form from Common Name
				upn := strings.Join(signer.DNSNames, ";")
				if len(upn) == 0 {
					upn = fmt.Sprintf("%s@mil", edipi)
				}

				serial := signer.SerialNumber
				issuer := signer.Issuer
				ca := signer.Issuer.CommonName

				// dates may not be necessary but nice to know we have timeline coverage
				notBefore := signer.NotBefore
				notAfter := signer.NotAfter

				// Put everything together into format strings
				fmtName := fmt.Sprintf("Name: %s, %s %s", lName, fName, mName)
				fmtEmail := ""
				if email != "" {
					fmtEmail = fmt.Sprintf("Email: %s", email)
				} else {
					fmtEmail = fmt.Sprintf("Email: %s", from)
				}
				fmtEdiPI := fmt.Sprintf("EDIPI: %s", edipi)
				fmtUpn := fmt.Sprintf("Principle Name: %s", upn)
				fmtSerial := fmt.Sprintf("Serial: %x", serial)
				fmtIssuer := fmt.Sprintf("Issuer: %s", issuer)
				fmtCA := fmt.Sprintf("Certificate Authority: %s", ca)
				fmtNotBefore := fmt.Sprintf("Not Before: %s", notBefore)
				fmtNotAfter := fmt.Sprintf("Not After: %s", notAfter)
				// Join all the formatted strings
				fmtSlice := []string{fmtName, fmtEmail, fmtEdiPI, fmtUpn, fmtSerial, fmtIssuer, fmtCA, fmtNotBefore, fmtNotAfter}
				cert := strings.Join(fmtSlice, "\n")
				// log.Println(cert)

				// send the cert accross the channel
				c <- cert
			}
		}
	}
}

// GetSubFolders is a recursive function which retrieves all sub-folders for the specified folder.
func GetSubFolders(pstFile pst.File, folder pst.Folder, formatType string, encryptionType string, c chan string) error {
	subFolders, err := pstFile.GetSubFolders(folder, formatType, encryptionType)

	if err != nil {
		return err
	}

	for _, subFolder := range subFolders {
		if !(subFolder.DisplayName == "Top of Outlook data file" || subFolder.DisplayName == "Top of Personal Folders" || subFolder.DisplayName == "Sent Items" || subFolder.DisplayName == "top of information store" || subFolder.DisplayName == "sent items") {
			continue
		}
		log.Printf("Parsing sub-folder: %s\n", subFolder.DisplayName)

		messages, err := pstFile.GetMessages(subFolder, formatType, encryptionType)

		if err != nil {
			return err
		}

		if len(messages) > 0 {
			log.Printf("Found %d messages.\n", len(messages))
			// process messages in parallel
			mChan := make(chan string)
			for i, msg := range messages {
				log.Printf("PROCESSING MESSAGE # %d", i)
				go processMsg(msg, pstFile, formatType, encryptionType, mChan)
				msgMsg := <-mChan
				c <- msgMsg
			}
		}

		if subFolder.HasSubFolders {
			err = GetSubFolders(pstFile, subFolder, formatType, encryptionType, c)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
