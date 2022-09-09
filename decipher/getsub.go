// GetSubFolders is a recursive function which retrieves all sub-folders for the specified folder.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pst "github.com/mooijtech/go-pst/v4/pkg"
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
		// numbered filenames for output
		fileNum := 1

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
					// decipher
					pt, err := decipher(attachBytes, certKeyPairs, cErr)
					if err != nil {
						continue
					}
					header, err := msg.GetHeaders(&pstFile, formatType, encryptionType)
					if err != nil {
						cErr <- "Failed to get msg headers"
						continue
					}
					// Filter out Content-Type and Content-Transfer-Encoding headers
					filteredHeaders := filterHeaders(header)
					outMsg := filteredHeaders + string(pt)
					// TODO: Check if we need to drill down - encrypted envelope inside another
					// TODO: re-assemble multipart tree if necessary
					basePath := filepath.Join(outPath, subFolder.DisplayName)
					basePath = strings.ReplaceAll(basePath, " ", "_")
					fmt.Println(basePath)
					err = os.MkdirAll(basePath, 0777)
					if err != nil {
						fmt.Println(err)
						cErr <- "Failed to make output dir"
						continue
					}
					fullPath := filepath.Join(basePath, fmt.Sprint(fileNum)+".eml")
					fileNum++
					fmt.Println(fullPath)
					err = os.WriteFile(fullPath, []byte(outMsg), 0666)
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
