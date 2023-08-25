package main

import (
	"fmt"
	"os"
	"time"

	pst "github.com/mooijtech/go-pst/v6/pkg"
	"github.com/mooijtech/go-pst/v6/pkg/properties"
	"github.com/rotisserie/eris"
	"golang.org/x/text/encoding"

	charsets "github.com/emersion/go-message/charset"
)

func main() {
	pst.ExtendCharsets(func(name string, enc encoding.Encoding) {
		charsets.RegisterEncoding(name, enc)
	})

	startTime := time.Now()

	fmt.Println("Initializing...")

	reader, err := os.Open("./mcflip.pst")

	if err != nil {
		panic(fmt.Sprintf("Failed to open PST file: %+v\n", err))
	}

	pstFile, err := pst.New(reader)

	if err != nil {
		panic(fmt.Sprintf("Failed to open PST file: %+v\n", err))
	}

	defer func() {
		pstFile.Cleanup()

		if errClosing := reader.Close(); errClosing != nil {
			panic(fmt.Sprintf("Failed to close PST file: %+v\n", err))
		}
	}()

	// Create attachments directory
	if _, err := os.Stat("attachments"); err != nil {
		if err := os.Mkdir("attachments", 0755); err != nil {
			panic(fmt.Sprintf("Failed to create attachments directory: %+v", err))
		}
	}

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
			case *properties.Appointment:
				//fmt.Printf("Appointment: %s\n", messageProperties.String())
			case *properties.Contact:
				//fmt.Printf("Contact: %s\n", messageProperties.String())
			case *properties.Task:
				//fmt.Printf("Task: %s\n", messageProperties.String())
			case *properties.RSS:
				//fmt.Printf("RSS: %s\n", messageProperties.String())
			case *properties.AddressBook:
				//fmt.Printf("Address book: %s\n", messageProperties.String())
			case *properties.Message:
				fmt.Printf("Subject: %s\n", messageProperties.GetSubject())
			case *properties.Note:
				//fmt.Printf("Note: %s\n", messageProperties.String())
			default:
				fmt.Printf("Unknown message type\n")
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

				var attachmentOutputPath string

				if attachment.GetAttachLongFilename() != "" {
					attachmentOutputPath = fmt.Sprintf("attachments/%d-%s", attachment.Identifier, attachment.GetAttachLongFilename())
				} else {
					attachmentOutputPath = fmt.Sprintf("attachments/UNKNOWN_%d", attachment.Identifier)
				}

				attachmentOutput, err := os.Create(attachmentOutputPath)

				if err != nil {
					return err
				}

				if _, err := attachment.WriteTo(attachmentOutput); err != nil {
					return err
				}

				if err := attachmentOutput.Close(); err != nil {
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

	fmt.Printf("Time: %s\n", time.Since(startTime).String())
}
