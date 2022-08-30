package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"

	pst "github.com/mooijtech/go-pst/v4/pkg"
	pkcs7 "go.mozilla.org/pkcs7"
)

func main() {
	pstFile, err := pst.NewFromFile("data/TEST.pst")

	if err != nil {
		fmt.Printf("Failed to create PST file: %s\n", err)
		return
	}

	defer func() {
		err := pstFile.Close()

		if err != nil {
			fmt.Printf("Failed to close PST file: %s", err)
		}
	}()

	fmt.Printf("Parsing file...")

	isValidSignature, err := pstFile.IsValidSignature()

	if err != nil {
		fmt.Printf("Failed to read signature: %s\n", err)
		return
	}

	if !isValidSignature {
		fmt.Printf("Invalid file signature.\n")
		return
	}

	contentType, err := pstFile.GetContentType()

	if err != nil {
		fmt.Printf("Failed to get content type: %s\n", err)
		return
	}

	fmt.Printf("Content type: %s\n", contentType)

	formatType, err := pstFile.GetFormatType()

	if err != nil {
		fmt.Printf("Failed to get format type: %s\n", err)
		return
	}

	fmt.Printf("Format type: %s\n", formatType)

	encryptionType, err := pstFile.GetEncryptionType(formatType)

	if err != nil {
		fmt.Printf("Failed to get encryption type: %s\n", err)
		return
	}

	fmt.Printf("Encryption type: %s\n", encryptionType)

	fmt.Printf("Initializing B-Trees...\n")

	err = pstFile.InitializeBTrees(formatType)

	if err != nil {
		fmt.Printf("Failed to initialize node and block b-tree.\n")
		return
	}

	rootFolder, err := pstFile.GetRootFolder(formatType, encryptionType)

	if err != nil {
		fmt.Printf("Failed to get root folder: %s\n", err)
		return
	}

	foundSignature := false
	err = GetSubFolders(pstFile, rootFolder, formatType, encryptionType, &foundSignature)

	if err != nil {
		fmt.Printf("Failed to get sub-folders: %s\n", err)
		return
	}
}

// GetSubFolders is a recursive function which retrieves all sub-folders for the specified folder.
func GetSubFolders(pstFile pst.File, folder pst.Folder, formatType string, encryptionType string, foundSignature *bool) error {
	fmt.Println(*foundSignature)
	if *foundSignature {
		return nil
	}
	subFolders, err := pstFile.GetSubFolders(folder, formatType, encryptionType)

	if err != nil {
		return err
	}

	for _, subFolder := range subFolders {
		fmt.Printf("Parsing sub-folder: %s\n", subFolder.DisplayName)
		// *** Custom Code below by McFlip ***
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
				myAttachments, err := msg.GetAttachments(&pstFile, formatType, encryptionType)
				if err != nil {
					return err
				}
				// fmt.Println("***Has Attachments***")
				// subj, _ := msg.GetSubject(&pstFile, formatType, encryptionType)
				// fmt.Println(subj)
				// body, _ := msg.GetBody(&pstFile, formatType, encryptionType)
				// fmt.Println(body)
				for _, attachment := range myAttachments {
					mimeType, _ := attachment.GetString(14094)
					// fmt.Println(mimeType)
					// fileName, _ := attachment.GetLongFilename()
					// fmt.Printf("%d: %s \n", i, fileName)
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
					mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
					if err != nil {
						return err
					}
					fmt.Println("mediaType:", mediaType)
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
							// fmt.Println(slurp)
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
							fmt.Println(cn)
							*foundSignature = true
						}
					}
				}
			}
		}

		if !*foundSignature {

			err = GetSubFolders(pstFile, subFolder, formatType, encryptionType, foundSignature)

			if err != nil {
				return err
			}
		}

	}

	return nil
}
