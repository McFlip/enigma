// Parse certificate info from signed emails. This info helps you fetch keys from escrow.
package main

import (
	"bufio"
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
	"regexp"
	"strings"

	pkcs7 "go.mozilla.org/pkcs7"

	"golang.org/x/text/encoding"

	pst "github.com/mooijtech/go-pst/v6/pkg"
	"github.com/mooijtech/go-pst/v6/pkg/properties"
	"github.com/rotisserie/eris"

	charsets "github.com/emersion/go-message/charset"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: .\\getSigs.exe <inputDir> <outputDir>")
		fmt.Println(
			"<inputDir>: source directory of input PSTs containing signed emails sent by the custodians",
		)
		fmt.Println(
			"<outputDir>: the file 'commonNames.txt' will be output here. It will contain common names which includes EDIPI #s.",
		)
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
		log.Fatal("Failed to walk input dir", err)
	}
	if len(files) == 0 {
		log.Fatal("Error: input dir is empty")
	}

	// process each pst in a goroutine
	// get cert back in channel
	c := make(chan string)
	var commonNames []string
	for _, file := range files {
		go processPST(file, c)
	}
	for completedFiles := 0; completedFiles < len(files); completedFiles++ {
		currMsg := <-c
		if currMsg == "" {
			continue
		}
		log.Println("FOUND: ", currMsg)
		commonNames = append(commonNames, currMsg)
	}
	err = os.WriteFile(
		filepath.Join(outDir, "commonName.txt"),
		[]byte(strings.Join(commonNames, "\n")),
		0666,
	)
	if err != nil {
		log.Fatal("failed to write output to commonName.txt")
	}
}

// goroutine processes 1 pst
func processPST(file string, c chan string) {
	pst.ExtendCharsets(func(name string, enc encoding.Encoding) {
		charsets.RegisterEncoding(name, enc)
	})

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Panic: %+v\n", r)
		}
	}()

	reader, err := os.Open(file)
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
			log.Printf("Failed to close PST file: %+v\n", err)
		}
		c <- ""
	}()

	// Walk through folders.
	if err := pstFile.WalkFolders(func(folder *pst.Folder) error {
		fmt.Printf("Walking folder: %s\n", folder.Name)

		// Only iterate through messages in Sent Items
		// if !(folder.Name == "Sent Items" || folder.Name == "sent items") {
		if folder.Name != "Sent Items" && folder.Name != "sent items" {
			return nil
		}

		messageIterator, err := folder.GetMessageIterator()

		if eris.Is(err, pst.ErrMessagesNotFound) {
			// Folder has no messages.
			return nil
		} else if err != nil {
			return err
		}

		// Iterate through messages.
		for messageIterator.Next() {
			// Only process messages
			message := messageIterator.Value()
			switch message.Properties.(type) {
			case *properties.Message:
				// Check to see if this is a signed message.
				// Message class will be "IPM.Note.SMIME.MultipartSigned"
				msgId := message.Identifier
				file := message.File
				messageNode, err := file.GetNodeBTreeNode(msgId)
				if err != nil {
					return eris.Wrap(err, "failed to find node b-tree node")
				}

				messageDataNode, err := file.GetBlockBTreeNode(messageNode.DataIdentifier)
				if err != nil {
					return eris.Wrap(err, "failed to find block b-tree node")
				}

				messageHeapOnNode, err := file.GetHeapOnNode(messageDataNode)
				if err != nil {
					return eris.Wrap(err, "failed to get Heap-on-Node")
				}

				localDescriptors, err := file.GetLocalDescriptors(messageNode)
				if err != nil {
					return eris.Wrap(err, "failed to find local descriptors")
				}

				propertyContext, err := file.GetPropertyContext(messageHeapOnNode)
				if err != nil {
					return eris.Wrap(err, "failed to get property context")
				}

				messageClassPropertyReader, err := propertyContext.GetPropertyReader(26, localDescriptors)
				if err != nil {
					return eris.Wrap(err, "failed to get property reader")
				}
				messageClass, err := messageClassPropertyReader.GetString()
				if err != nil {
					return eris.Wrap(err, "failed to get message class")
				}

				if messageClass != "IPM.Note.SMIME.MultipartSigned" {
					continue
				}
			default:
				continue
			}
			// Signed emails will have a SMIME.p7m attachment
			attachmentIterator, err := message.GetAttachmentIterator()
			if eris.Is(err, pst.ErrAttachmentsNotFound) {
				// This message has no attachments.
				continue
			} else if err != nil {
				return err
			}

			for attachmentIterator.Next() {
				attachment := attachmentIterator.Value()
				// check for content type
				// signed emails will be of content-type application/(x-)pkcs7-signature and message class IPM.Note.SMIME.MultipartSigned
				// encrypted emails will be of content-type application/(x-)pkcs7-mime and message class IPM.Note.SMIME
				// Note: the content-type may or may not be of the extended 'x-' variety so a regex is used
				// Note: the filenames 'smime.p7s' and 'smime.p7m' may or may not be capitalized, so I avoid keying off the filename
				// sigContentType := regexp.MustCompile(`application/x?-?pkcs7-signature`)
				sigContentType := regexp.MustCompile(`multipart/signed`)
				if ok := sigContentType.MatchString(attachment.GetAttachMimeTag()); !ok {
					log.Println("Content-Type not matched")
					continue
				}
				// DEBUG: io.Pipe not working with attachment.WriteTo
				bufBs := make([]byte, 0, attachment.GetAttachSize())
				buf := bytes.NewBuffer(bufBs)
				w := bufio.NewWriter(buf)
				_, err := attachment.WriteTo(w)
				if err != nil {
					log.Println("Failed to write attachment", err)
					c <- ""
					continue
				}
				// log.Println("Wrote attachment bytes: ", n)
				w.Flush()
				msg, err := mail.ReadMessage(buf)
				if err != nil {
					log.Println("Failed to read message", err)
					c <- ""
					continue
				}
				var bodyBytes []byte
				if _, err = msg.Body.Read(bodyBytes); err != nil {
					log.Println("Failed to read msg body", err)
					c <- ""
					continue
				}

				// Iterate through msg parts until we get to the smime.p7s
				_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
				if err != nil {
					log.Println("Failed to parse media type", err)
					c <- ""
					continue
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
						log.Println("Failed to get next part", err)
						c <- ""
						continue
					}
					partEncoding := p.Header["Content-Transfer-Encoding"]
					if len(partEncoding) == 0 {
						continue
					}
					if partEncoding[0] != "base64" {
						continue
					}
					slurp, err := io.ReadAll(p)
					if err != nil {
						log.Println("Failed to read part", err)
						c <- ""
						continue
					}
					// parse the pkcs7 struct
					dst := make([]byte, len(slurp))
					n, err := base64.StdEncoding.Decode(dst, slurp)
					if err != nil {
						log.Println("Failed to base64 decode", err)
						// c <- ""
						continue
					}
					dst = dst[:n]
					p7m, err := pkcs7.Parse(dst)
					if err != nil {
						log.Println("Failed to parse pkcs7 object", err)
						c <- ""
						continue
					}

					// Get the signer info - this is the main objective!
					signer := p7m.GetOnlySigner()

					// Common Name is in the form LAST.FIRST.MIDDLE.EDIPI
					cn := signer.Subject.CommonName
					c <- cn
				}
			}
		}
		return messageIterator.Err()
	}); err != nil {
		c <- ""
		return
	}

	c <- ""
}
