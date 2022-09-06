// GetSubFolders is a recursive function which retrieves all sub-folders for the specified folder.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pst "github.com/mooijtech/go-pst/v4/pkg"
	"go.mozilla.org/pkcs7"
)

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
