// Parse EDIPI numbers from Common Name field in signed emails
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

	// "strconv"

	pst "github.com/mooijtech/go-pst/v4/pkg"
	pkcs7 "go.mozilla.org/pkcs7"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: enigma <inputDir> <outputDir>")
		fmt.Println("<inputDir>: source directory of input PSTs containing signed emails sent by the custodians")
		fmt.Println("<outputDir>: the file 'allCerts.txt' will be output here. It will contain all common names parsed.")
		os.Exit(1)
	}
	inDir := os.Args[1]
	// outDir := os.Args[2]

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
	// get common name back in channel
	// use a map to dedup with EDIPI as the key
	c := make(chan string)
	// allCerts := make(map[int]string)
	allCerts := ""
	for _, file := range files {
		go processPST(file, c)
	}
	for i := 0; i < len(files); i++ {
		cn := <-c
		allCerts = allCerts + cn
		// expect cn to be in form LAST.FIRST.MIDDLE.12345678
		// cnSlice := strings.Split(cn, ".")
		// certKey, err := strconv.Atoi(cnSlice[len(cnSlice)-1])
		// if err != nil {
		// 	log.Fatal("Can't parse EDIPI #")
		// }
		// allCerts[certKey] = cn
	}
	// write out the allCerts.txt file
	fmt.Println(allCerts)
	// allCertsStr := ""
	// for _, val := range allCerts {
	// 	allCertsStr = allCertsStr + val + "\n"
	// }
	// err = os.WriteFile(filepath.Join(outDir, "allCerts.txt"), []byte(allCertsStr), 0666)
	// if err != nil {
	// 	log.Fatal("failed to write output to allCerts.txt")
	// }
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

	// fmt.Printf("Parsing file...")

	isValidSignature, err := pstFile.IsValidSignature()

	if err != nil {
		fmt.Printf("Failed to read signature: %s\n", err)
		c <- ""
		return
	}

	if !isValidSignature {
		fmt.Printf("Invalid file signature.\n")
		c <- ""
		return
	}

	formatType, err := pstFile.GetFormatType()

	if err != nil {
		fmt.Printf("Failed to get format type: %s\n", err)
		c <- ""
		return
	}

	// fmt.Printf("Format type: %s\n", formatType)

	encryptionType, err := pstFile.GetEncryptionType(formatType)

	if err != nil {
		fmt.Printf("Failed to get encryption type: %s\n", err)
		c <- ""
		return
	}

	// fmt.Printf("Encryption type: %s\n", encryptionType)

	// fmt.Printf("Initializing B-Trees...\n")

	err = pstFile.InitializeBTrees(formatType)

	if err != nil {
		fmt.Printf("Failed to initialize node and block b-tree.\n")
		c <- ""
		return
	}

	rootFolder, err := pstFile.GetRootFolder(formatType, encryptionType)

	if err != nil {
		fmt.Printf("Failed to get root folder: %s\n", err)
		c <- ""
		return
	}

	foundSignature := false
	err = GetSubFolders(pstFile, rootFolder, formatType, encryptionType, &foundSignature, c)

	if err != nil {
		fmt.Printf("Failed to get sub-folders: %s\n", err)
		c <- ""
		return
	}
}

// GetSubFolders is a recursive function which retrieves all sub-folders for the specified folder.
func GetSubFolders(pstFile pst.File, folder pst.Folder, formatType string, encryptionType string, foundSignature *bool, c chan string) error {
	if *foundSignature {
		return nil
	}
	subFolders, err := pstFile.GetSubFolders(folder, formatType, encryptionType)

	if err != nil {
		return err
	}

	for _, subFolder := range subFolders {
		// fmt.Printf("Parsing sub-folder: %s\n", subFolder.DisplayName)
		if !(subFolder.DisplayName == "Top of Outlook data file" || subFolder.DisplayName == "Sent Items") {
			continue
		}

		messages, err := pstFile.GetMessages(subFolder, formatType, encryptionType)

		if err != nil {
			return err
		}

		if len(messages) > 0 {
			// fmt.Printf("Found %d messages.\n", len(messages))
			for _, msg := range messages {
				if *foundSignature {
					return nil
				}
				hasAttachments, err := msg.HasAttachments()
				if err != nil {
					return err
				}
				if !hasAttachments {
					continue
				}
				// from, err := msg.GetFrom(&pstFile, formatType, encryptionType)
				// if err != nil {
				// 	return err
				// }
				myAttachments, err := msg.GetAttachments(&pstFile, formatType, encryptionType)
				if err != nil {
					return err
				}
				for _, attachment := range myAttachments {
					mimeType, _ := attachment.GetString(14094)
					if mimeType != "multipart/signed" {
						continue
					}
					attachStream, err := attachment.GetInputStream(&pstFile, formatType, encryptionType)
					if err != nil {
						return err
					}
					attachBytes, err := attachStream.ReadCompletely()
					if err != nil {
						return err
					}
					msg, err := mail.ReadMessage(bytes.NewReader(attachBytes))
					if err != nil {
						log.Fatal(err)
					}
					_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
					if err != nil {
						return err
					}
					mr := multipart.NewReader(msg.Body, params["boundary"])
					for {
						p, err := mr.NextPart()
						if err == io.EOF {
							return nil
						}
						if err != nil {
							log.Fatal(err)
						}
						slurp, err := io.ReadAll(p)
						if err != nil {
							log.Fatal(err)
						}
						if p.Header.Get("Content-Type") == "application/pkcs7-signature; name=\"smime.p7s\"" {
							dst := make([]byte, len(slurp))
							n, err := base64.StdEncoding.Decode(dst, slurp)
							if err != nil {
								log.Fatal(err)
							}
							dst = dst[:n]
							p7m, err := pkcs7.Parse(dst)
							if err != nil {
								log.Fatal(err)
							}
							cn := p7m.GetOnlySigner().Subject.CommonName
							cnSplit := strings.Split(cn, ".")
							lName := cnSplit[0]
							fName := cnSplit[1]
							mName := ""
							edipi := cnSplit[len(cnSplit)-1]
							if len(cnSplit) == 4 {
								mName = cnSplit[2]
							}
							email := strings.Join(p7m.GetOnlySigner().EmailAddresses, ";") // just using "From" header
							upn := strings.Join(p7m.GetOnlySigner().DNSNames, ";")
							if len(upn) == 0 {
								upn = fmt.Sprintf("%s@mil", edipi)
							}
							serial := p7m.GetOnlySigner().SerialNumber
							issuer := p7m.GetOnlySigner().Issuer
							ca := p7m.GetOnlySigner().Issuer.CommonName
							fmtName := fmt.Sprintf("Name: %s, %s %s", lName, fName, mName)
							// fmtEmail := fmt.Sprintf("Email: %s", from)
							fmtEmail := fmt.Sprintf("Email: %s", email)
							fmtEdiPI := fmt.Sprintf("EDIPI: %s", edipi)
							fmtUpn := fmt.Sprintf("Principle Name: %s", upn)
							fmtSerial := fmt.Sprintf("Serial: %x", serial)
							fmtIssuer := fmt.Sprintf("Issuer: %s", issuer)
							fmtCA := fmt.Sprintf("Certificate Authority: %s", ca)
							cert := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s", fmtName, fmtEmail, fmtEdiPI, fmtUpn, fmtSerial, fmtIssuer, fmtCA)
							// *foundSignature = true
							c <- cert
						}
					}
				}
			}
		}

		if !*foundSignature {
			err = GetSubFolders(pstFile, subFolder, formatType, encryptionType, foundSignature, c)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
