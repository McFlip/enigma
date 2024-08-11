/*
Copyright © 2024 McFlip <grady.c.denton@yahoo.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	pst "github.com/mooijtech/go-pst/v6/pkg"
	"github.com/mooijtech/go-pst/v6/pkg/properties"
	"github.com/rotisserie/eris"
	"golang.org/x/text/encoding"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	charsets "github.com/emersion/go-message/charset"
)

var header_in, header_out *string

// getheadersCmd represents the getheaders command
var getheadersCmd = &cobra.Command{
	Use:   "getheaders",
	Short: "Get metadata from email headers",
	Long: `Get metadata from email headers

  Place input PST files in header_in
  Tab delimited csv file will output in header_out

  *NOTE* This only looks at email headers 1 level deep.
  It will not examine emails attached to other emails`,
	Run: func(cmd *cobra.Command, args []string) {
		viper.SetDefault("header.header_in", "header_in")
		*header_in = viper.GetString("header.header_in")
		viper.SetDefault("header.header_out", "header_out")
		*header_out = viper.GetString("header.header_out")

		var outDir string
		var logFile *os.File

		pst.ExtendCharsets(func(name string, enc encoding.Encoding) {
			charsets.RegisterEncoding(name, enc)
		})

		// Walk PST files
		filepath.Walk(*header_in, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				log.Fatal(err)
			}

			if info.IsDir() {
				// Processing custodian folder
				// close previous custodian's log
				if logFile != nil {
					logFile.Sync()
					logFile.Close()
				}

				// for custodian input dir create custodian output dir
				base := filepath.Base(path)
				if base == *header_in {
					return nil
				}
				outDir = filepath.Join(*header_out, base)
				err := os.Mkdir(outDir, 0755)
				if err != nil {
					log.Fatal(
						"Error making custodian subfolder in header_out outpath ",
						outDir,
						" err: ",
						err,
					)
				}

				// open log
				logPath := filepath.Join(outDir, "headerMetaData.tsv")
				if _, err := os.Stat(logPath); err != nil {
					if errors.Is(err, os.ErrNotExist) {
						logFile, err = os.OpenFile(
							logPath,
							os.O_WRONLY|os.O_CREATE|os.O_APPEND,
							0644,
						)
						if err != nil {
							log.Fatalf("Can't open log file %s to write results", logPath)
						}
						// TSV header
						logFile.WriteString(
							"PstFile\tFolder\tFrom\tSenderName\tTo\tCC\tBCC\tSubj\tDate\tMessage-Id\tHasAttachments\tIsEncrypted\tAttachmentFileNames\n",
						)
					}
				} else {
					logFile, err = os.OpenFile(
						logPath,
						os.O_WRONLY|os.O_CREATE|os.O_APPEND,
						0644,
					)
					if err != nil {
						log.Fatalf("Can't open log file %s to write results", logPath)
					}
				}
			} else {

				// Processing custodian PST files

				// open file; create reader
				if filepath.Ext(info.Name()) != ".pst" {
					log.Fatal("getheaders input must be pst files")
				}
				reader, err := os.Open(path)
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

				// Walk through folders inside PST.
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
						// TODO: replace WriteString with just Write directly to byteslice for performance
						var b strings.Builder

						// We only care about messages, not calendar items etc.
						switch messageProperties := message.Properties.(type) {
						case *properties.Message:
							// fmt.Printf("DEBUG: %s\n", messageProperties.GetSubject())
							b.WriteString(fmt.Sprintf("%s\t", info.Name()))
							b.WriteString(fmt.Sprintf("%s\t", folder.Name))
							b.WriteString(fmt.Sprintf("%s\t", messageProperties.GetFrom()))
							b.WriteString(fmt.Sprintf("%s\t", messageProperties.GetSenderName()))
							b.WriteString(fmt.Sprintf("%s\t", messageProperties.GetDisplayTo()))
							b.WriteString(fmt.Sprintf("%s\t", messageProperties.GetDisplayCc()))
							b.WriteString(fmt.Sprintf("%s\t", messageProperties.GetDisplayBcc()))
							b.WriteString(fmt.Sprintf("%s\t", messageProperties.GetSubject()))
							// Date is encoded as Unix nanosecond timestamp
							timestamp := time.Unix(0, messageProperties.GetClientSubmitTime()).UTC()
							b.WriteString(fmt.Sprintf("%s\t", timestamp.Format(time.UnixDate)))
							b.WriteString(fmt.Sprintf("%s\t", messageProperties.GetInternetMessageId()))
							hasAttach, _ := message.HasAttachments()
							b.WriteString(fmt.Sprintf("%t\t", hasAttach))

							localdescriptors := message.LocalDescriptors
							messageClassPropertyReader, err := message.PropertyContext.GetPropertyReader(26, localdescriptors)
							if err != nil {
								return err
							}
							messageClass, err := messageClassPropertyReader.GetString()
							if err != nil {
								return err
							}
							// is this encrypted?
							b.WriteString(fmt.Sprintf("%t\t", messageClass == "IPM.Note.SMIME"))

						default:
							// anything not a message
							continue
						}

						attachmentIterator, err := message.GetAttachmentIterator()

						if eris.Is(err, pst.ErrAttachmentsNotFound) {
							// This message has no attachments.
							// b.WriteRune('\t')
							logEntry := b.String()
							// fmt.Println(logEntry)
							logFile.WriteString(logEntry)
							continue
						} else if err != nil {
							return err
						}

						for attachmentIterator.Next() {
							attachment := attachmentIterator.Value()

							// var attachmentName string
							attachmentName := attachment.GetAttachLongFilename()

							if attachmentName == "" {
								attachmentName = fmt.Sprintf("UNKNOWN_%d", attachment.Identifier)
							}
							b.WriteString(fmt.Sprintf("%s;", attachmentName))

							if attachmentIterator.Err() != nil {
								return attachmentIterator.Err()
							}
						}
						b.WriteRune('\n')
						logEntry := b.String()
						// fmt.Printf("DEBUG: %s\n", logFile.Name())
						logFile.WriteString(logEntry)
						// fmt.Println(logFile.Sync())
						// fmt.Println(logEntry)
					}

					return messageIterator.Err()
				}); err != nil {
					panic(fmt.Sprintf("Failed to walk folders: %+v\n", err))
				}
			}
			return nil
		})
		if logFile != nil {
			logFile.Sync()
			logFile.Close()
		}
		log.Println("DONE!")
	},
}

func init() {
	rootCmd.AddCommand(getheadersCmd)

	header_in = decipherCmd.PersistentFlags().
		String("header_in", "", "Dir containing pst files where you want to parse headers. Make a subfolder for each custodian under this.")
	viper.BindPFlag("header.header_in", decipherCmd.PersistentFlags().Lookup("header_in"))
	header_out = decipherCmd.PersistentFlags().
		String("header_out", "", "Dir for output logs. There will be a subfolder for each custodian.")
	viper.BindPFlag("header.header_out", decipherCmd.PersistentFlags().Lookup("header_out"))
}
