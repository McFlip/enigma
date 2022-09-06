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

	pst "github.com/mooijtech/go-pst/v4/pkg"
	"github.com/youmark/pkcs8"
	"go.mozilla.org/pkcs7"
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

// TODO: Bust out other funcs into separate files

// processes 1 pst
func processPST(file string, outDir string, certKeyPairs []certKeyPair) error {
	pstFile, err := pst.NewFromFile(file)

	if err != nil {
		fmt.Printf("Failed to create PST file: %s\n", err)
		return err
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
		return err
	}

	if !isValidSignature {
		fmt.Printf("Invalid file signature.\n")
		return err
	}

	formatType, err := pstFile.GetFormatType()

	if err != nil {
		fmt.Printf("Failed to get format type: %s\n", err)
		return err
	}

	// fmt.Printf("Format type: %s\n", formatType)

	encryptionType, err := pstFile.GetEncryptionType(formatType)

	if err != nil {
		fmt.Printf("Failed to get encryption type: %s\n", err)
		return err
	}

	// fmt.Printf("Encryption type: %s\n", encryptionType)

	// fmt.Printf("Initializing B-Trees...\n")

	err = pstFile.InitializeBTrees(formatType)

	if err != nil {
		fmt.Printf("Failed to initialize node and block b-tree.\n")
		return err
	}

	rootFolder, err := pstFile.GetRootFolder(formatType, encryptionType)

	if err != nil {
		fmt.Printf("Failed to get root folder: %s\n", err)
		return err
	}

	// numSubFolders tracks how far we have decended and how many goroutines we must wait on
	// cSub signals decending 1 level; lauching goroutine
	// cDone signals ascending back 1 level; goroutine is done
	// cErr is for error signaling
	cSub := make(chan string)
	cDone := make(chan string)
	cErr := make(chan string)
	numSubFolders := 0
	go GetSubFolders(pstFile, rootFolder, formatType, encryptionType, file, outDir, certKeyPairs, cSub, cDone, cErr)

	for {
		select {
		case dive := <-cSub:
			numSubFolders++
			fmt.Println(dive)
		case done := <-cDone:
			numSubFolders--
			fmt.Println(done)
		case err := <-cErr:
			fmt.Println(err)
			// case <-cErr:
			// 	fmt.Println("Fubar")
		}
		if numSubFolders < 0 {
			break
		}
	}

	return nil
}

// GetSubFolders is a recursive function which retrieves all sub-folders for the specified folder.
func GetSubFolders(pstFile pst.File, folder pst.Folder, formatType string, encryptionType string, target string, outPath string, certKeyPairs []certKeyPair, cSub chan string, cDone chan string, cErr chan string) {
	subFolders, err := pstFile.GetSubFolders(folder, formatType, encryptionType)

	if err != nil {
		cErr <- err.Error()
		cDone <- fmt.Sprint("Failed to get subfolders for ", folder.DisplayName)
		return
	}

	for _, subFolder := range subFolders {
		// cSub <- "Dive!"
		fmt.Printf("Parsing sub-folder: %s\n", subFolder.DisplayName)

		messages, err := pstFile.GetMessages(subFolder, formatType, encryptionType)

		if err != nil {
			cErr <- err.Error()
			cDone <- fmt.Sprint("Failed to get messages for ", subFolder.DisplayName)
			return
		}

		if len(messages) > 0 {
			fmt.Printf("Found %d messages.\n", len(messages))
			for _, msg := range messages {
				// get header fields
				from, _ := msg.GetFrom(&pstFile, formatType, encryptionType)
				to, _ := msg.GetTo(&pstFile, formatType, encryptionType)
				cc, _ := msg.GetCC(&pstFile, formatType, encryptionType)
				bcc, _ := msg.GetBCC(&pstFile, formatType, encryptionType)
				subj, _ := msg.GetSubject(&pstFile, formatType, encryptionType)
				date, _ := msg.GetReceivedDate()
				msgId, _ := msg.GetMessageID(&pstFile, formatType, encryptionType)
				attachments, _ := msg.GetAttachments(&pstFile, formatType, encryptionType)
				attachStr := ""
				for _, attachment := range attachments {
					filename, _ := attachment.GetLongFilename()
					attachStr = attachStr + filename + ";"
				}
				logStr := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t", target, from, to, cc, bcc, subj, date, msgId, attachStr)
				hasAttachments, err := msg.HasAttachments()
				if err != nil {
					logStr = logStr + err.Error() + "\n"
					cErr <- logStr
					continue
				}
				if !hasAttachments {
					continue
				}
				myAttachments, err := msg.GetAttachments(&pstFile, formatType, encryptionType)
				if err != nil {
					logStr = logStr + err.Error() + "\n"
					cErr <- logStr
					continue
				}
				for _, attachment := range myAttachments {
					// TODO: handle opaque signed email
					// TODO: check for special case of PT parent w/ CT children
					mimeType, _ := attachment.GetString(14094)
					fmt.Println(mimeType)
					if mimeType != "application/pkcs7-mime" {
						continue
					}
					fmt.Println("$$$$$$$$$$$$$$$$$$")
					fmt.Println(logStr)
					attachStream, err := attachment.GetInputStream(&pstFile, formatType, encryptionType)
					if err != nil {
						cErr <- err.Error()
						continue
					}
					attachBytes, err := attachStream.ReadCompletely()
					if err != nil {
						cErr <- err.Error()
						continue
					}

					// os.WriteFile("smime.p7m", attachBytes, 0666)
					p7m, err := pkcs7.Parse(attachBytes)
					if err != nil {
						fmt.Println(err)
						cErr <- err.Error()
						continue
					}
					fmt.Println("$$$$$$$$$$$$$$$$$$")
					var pt []byte
					for i, certKeyPair := range certKeyPairs {
						// fmt.Println(certKeyPair)
						pt, err = p7m.Decrypt(certKeyPair.cert, certKeyPair.privKey)
						if err != nil {
							fmt.Println(err)
							if i == len(certKeyPairs)-1 {
								cErr <- "No matching cert-key pair"
								continue
							}
						}
					}
					// fmt.Println(string(pt))
					header, err := msg.GetHeaders(&pstFile, formatType, encryptionType)
					if err != nil {
						cErr <- "Failed to get msg headers"
						continue
					}
					outMsg, _, found := strings.Cut(header, "MIME-Version")
					if err != nil || !found {
						cErr <- "Failed to truncate headers"
						continue
					}
					outMsg = outMsg + string(pt)
					// TODO: Check if we need to drill down - encrypted envelope inside another
					// TODO: re-assemble multipart tree if necessary
					outPath = filepath.Join(outPath, subFolder.DisplayName)
					outPath = strings.ReplaceAll(outPath, " ", "_")
					fmt.Println(outPath)
					err = os.MkdirAll(outPath, 0777)
					if err != nil {
						fmt.Println(err)
						cErr <- "Failed to make output dir"
						continue
					}
					// TODO: loop through outPath and find next available name
					outPath = filepath.Join(outPath, "1.eml")
					fmt.Println(outPath)
					err = os.WriteFile(outPath, []byte(outMsg), 0666)
					if err != nil {
						fmt.Println(err)
						cErr <- "Failed to write out .eml file"
						continue
					}
				}
			}
		}
		if subFolder.HasSubFolders {
			cSub <- "Dive!"
			outPath = filepath.Join(outPath, subFolder.DisplayName)
			go GetSubFolders(pstFile, subFolder, formatType, encryptionType, target, outPath, certKeyPairs, cSub, cDone, cErr)
		} else {
			fmt.Println("Leaf node", subFolder.DisplayName)
		}
	}
	cDone <- "done"

}
