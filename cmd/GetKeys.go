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

	// "github.com/McFlip/enigma/getkeys"

	getkeys "github.com/McFlip/enigma/cmd/getKeys"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type p12Slc []getkeys.FnamePW

// GetKeysCmd represents the GetKeys command
var GetKeysCmd = &cobra.Command{
	Use:   "GetKeys",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("GetKeys called")
		viper.SetDefault("keys.p12Dir", "p12")
		*p12Dir = viper.GetString("keys.p12Dir")
		fmt.Println("p12:", *p12Dir)
		viper.SetDefault("keys.keysDir", "keys")
		*keysDir = viper.GetString("keys.keysDir")
		fmt.Println("keysDir:", *keysDir)
		viper.SetDefault("keys.certDir", "cert")
		*certDir = viper.GetString("keys.certDir")
		fmt.Println("certDir:", *certDir)
		*casePW = viper.GetString("keys.casePW")
		if casePW == nil {
			log.Fatal("Case password not configured!")
		}
		fmt.Println("casePW:", *casePW)

		// unmarshall p12 filename-pw array
		var p12 p12Slc
		if err := viper.UnmarshalKey("keys.p12PWs", &p12); err != nil {
			log.Fatal("Failed to unmarshall p12 passwords: ", err)
		}
		fmt.Println("p12PWs: ", p12)
	},
}

var p12Dir, keysDir, certDir, casePW *string

func init() {
	rootCmd.AddCommand(GetKeysCmd)

	p12Dir = GetKeysCmd.PersistentFlags().
		String("p12Dir", "", "Dir containing p12 files from the RA/CA")
	viper.BindPFlag("keys.p12Dir", GetKeysCmd.PersistentFlags().Lookup("p12Dir"))
	keysDir = GetKeysCmd.PersistentFlags().String("keysDir", "", "Output dir for extracted keys")
	viper.BindPFlag("keys.keysDir", GetKeysCmd.PersistentFlags().Lookup("keysDir"))
	certDir = GetKeysCmd.PersistentFlags().
		String("certDir", "", "Output dir for extracted certificates")
	viper.BindPFlag("keys.certDir", GetKeysCmd.PersistentFlags().Lookup("certDir"))
	casePW = GetKeysCmd.PersistentFlags().
		String("casePW", "", "Master password you created for all keys")
	viper.BindPFlag("keys.casePW", GetKeysCmd.PersistentFlags().Lookup("casePW"))
}
