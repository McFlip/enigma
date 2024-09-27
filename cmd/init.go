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
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a case",
	Long: `  1. mkdir caseName
  2. cd caseName
  3. enigma init
  4. mkdir ct/custodianName
  5. cp config.example.yaml config.yaml
  6. edit config.yaml
  7. enigma someCommand`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Scaffolding case folders and creating example config.")
		if err := os.Mkdir("p12", 0774); err != nil {
			log.Fatal("unable to mkdir p12: ", err)
		}
		if err := os.Mkdir("keys", 0774); err != nil {
			log.Fatal("unable to mkdir keys: ", err)
		}
		if err := os.Mkdir("certs", 0774); err != nil {
			log.Fatal("unable to mkdir cert: ", err)
		}
		if err := os.Mkdir("signedPSTs", 0774); err != nil {
			log.Fatal("unable to mkdir signedPSTs: ", err)
		}
		if err := os.Mkdir("custodianInfo", 0774); err != nil {
			log.Fatal("unable to mkdir custodianInfo: ", err)
		}
		if err := os.Mkdir("ct", 0774); err != nil {
			log.Fatal("unable to mkdir ct: ", err)
		}
		if err := os.Mkdir("pt", 0774); err != nil {
			log.Fatal("unable to mkdir pt: ", err)
		}
		if err := os.Mkdir("header_in", 0774); err != nil {
			log.Fatal("unable to mkdir header_in: ", err)
		}
		if err := os.Mkdir("header_out", 0774); err != nil {
			log.Fatal("unable to mkdir header_out: ", err)
		}
		exampleCfg := `
decipher:
  ct: "ct" #Dir containing ciphertext emails. Make a subfolder for each custodian under this.
  pt: "pt" #Dir for output plaintext. There will be a subfolder for each custodian and a log folder under that.
  parallel: true # use multithreading in readpst when unpacking PST files
  eml: true # CT input will be loose .eml files instead of PST archives
keys:
  p12Dir: "p12" #Drop the p12 files you got from the Registration Authority here
  keysDir: "keys" #Output of GetKeys, Input of Decipher. The actual keys extracted from the p12 containers.
  certDir: "certs" #Output of GetKeys, Input of Decipher. Custodian public certificates extracted from the p12 containers.
  casePW: "" #Password you create to store the extracted keys. All keys will use this PW. Create a *STRONG* pw and save using a pw manager.
  p12PWs:
    - filename: "alice.p12" #1st p12 file name
      password: "P@ssw0rd" #password for 1st p12 file
    - filename: "bob.p12" #2nd p12 file name
      password: "S3cr3tSquirel" #password for 2nd p12 file
signed:
  pstDir: "signedPSTs" #Dir containing signed emails from custodians
  custodianInfoDir: "custodianInfo" #Output of getSigs. A txt file will be written with custodian IDs.
header:
  header_in: "header_in" #Dir for input pst files for getheaders. Make a subfolder for each custodian under this.
  header_out: "header_out" #Dir for for getheaders output logs. There will be a subfolder for each custodian.
`
		if err := os.WriteFile("config.example.yaml", []byte(exampleCfg), 0664); err != nil {
			log.Fatal("unable to create config file: ", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
