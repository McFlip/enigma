// processes 1 pst
package main

import (
	"fmt"
	"os"

	charsets "github.com/emersion/go-message/charset"
	pst "github.com/mooijtech/go-pst/v6/pkg"
	"github.com/mooijtech/go-pst/v6/pkg/properties"
	"github.com/rotisserie/eris"
	"golang.org/x/text/encoding"
)

func processPST(file string, outDir string, certKeyPairs []certKeyPair, msgExceptions *[]string) error {
	pst.ExtendCharsets(func(name string, enc encoding.Encoding) {
		charsets.RegisterEncoding(name, enc)
	})
	reader, err := os.Open(file)
	if err != nil {
		fmt.Printf("Failed to open PST file: %s\n", err)
		return err
	}
	pstFile, err := pst.New(reader)

	if err != nil {
		fmt.Printf("Failed to create PST file: %s\n", err)
		return err
	}

	defer func() {
		pstFile.Cleanup()

		if errClosing := reader.Close(); errClosing != nil {
			fmt.Printf("Failed to close PST file: %s", err)
		}
	}()

	// Walk through folders.
	if err := pstFile.WalkFolders(func(folder *pst.Folder) error {
		fmt.Printf("Walking folder: %s\n", folder.Name)

		messageIterator, err := folder.GetMessageIterator()

		if eris.Is(err, pst.ErrMessagesNotFound) {
			// Folder has no messages.
			return nil
		} else if err != nil {
			return err
		}

		// Iterate through messages.
		for messageIterator.Next() {
			message := messageIterator.Value()

			switch messageProperties := message.Properties.(type) {
			case *properties.Message:
				fmt.Printf("Subject: %s\n", messageProperties.GetSubject())
				// header := messageProperties.GetTransportMessageHeaders()
				body := messageProperties.GetBody()
				fmt.Println(body)
			default:
				continue
			}

			attachmentIterator, err := message.GetAttachmentIterator()

			if eris.Is(err, pst.ErrAttachmentsNotFound) {
				// This message has no attachments.
				continue
			} else if err != nil {
				return err
			}

			// Iterate through attachments.
			for attachmentIterator.Next() {
				attachment := attachmentIterator.Value()
				if attachment.GetAttachFilename() != "" {
					fmt.Println(attachment.GetAttachFilename())
				} else {
					fmt.Println("No attach filename")
				}
				attachOut, err := os.Create("fubar.eml")
				if err != nil {
					return err
				}
				attachment.WriteTo(attachOut)
				if err != nil {
					return err
				}

			}

			if attachmentIterator.Err() != nil {
				return attachmentIterator.Err()
			}
		}
		return messageIterator.Err()
	}); err != nil {
		panic(fmt.Sprintf("Failed to walk folders: %+v\n", err))
	}

	/*
		target := filepath.Base(file)
		outPath := filepath.Join(outDir, target)
		err = GetSubFolders(pstFile, rootFolder, formatType, encryptionType, target, outPath, certKeyPairs, msgExceptions)
	*/
	return err
}
