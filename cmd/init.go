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
  4. cp config.example.yaml config.yaml
  5. edit config.yaml
  6. enigma someCommand`,
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
		if err := os.Mkdir("signed", 0774); err != nil {
			log.Fatal("unable to mkdir signed: ", err)
		}
		if err := os.Mkdir("ct", 0774); err != nil {
			log.Fatal("unable to mkdir ct: ", err)
		}
		if err := os.Mkdir("pt", 0774); err != nil {
			log.Fatal("unable to mkdir pt: ", err)
		}
		exampleCfg := `
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
`
		if err := os.WriteFile("config.example.yaml", []byte(exampleCfg), 0664); err != nil {
			log.Fatal("unable to create config file: ", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
