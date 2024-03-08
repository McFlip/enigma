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
	getsigs "github.com/McFlip/enigma/cmd/getSigs"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// getSigsCmd represents the getSigs command
var getSigsCmd = &cobra.Command{
	Use:   "getSigs",
	Short: "Get Custodian metadata from signed emails in sent items",
	Long: `Get Custodian metadata from signed emails in sent items
  
  Extract custodian IDs from CN field in certs from signed emails
  Input is a folder of PST files with signed emails sent by the custodian
  Output is custodian metadata`,
	Run: func(cmd *cobra.Command, args []string) {
		viper.SetDefault("signed.pstDir", "signedPSTs")
		*pstDir = viper.GetString("signed.pstDir")
		viper.SetDefault("signed.custodianInfoDir", "custodianInfo")
		*custodianInfoDir = viper.GetString("signed.custodianInfoDir")

		getsigs.GetSigs(*pstDir, *custodianInfoDir)
	},
}

var pstDir, custodianInfoDir *string

func init() {
	rootCmd.AddCommand(getSigsCmd)

	pstDir = getSigsCmd.PersistentFlags().
		String("pstDir", "", "source directory of input PSTs containing signed emails sent by the custodians")
	viper.BindPFlag("signed.pstDir", getSigsCmd.PersistentFlags().Lookup("pstDir"))
	custodianInfoDir = getSigsCmd.PersistentFlags().
		String("custodianInfoDir", "", "the file 'commonNames.txt' will be output here. It will contain common names which includes EDIPI #s.")
	viper.BindPFlag(
		"signed.custodianInfoDir",
		getSigsCmd.PersistentFlags().Lookup("custodianInfoDir"),
	)
}
