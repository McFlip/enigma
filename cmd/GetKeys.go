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
	"log"
	"path/filepath"

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
		viper.SetDefault("keys.p12Dir", "p12")
		*p12Dir = viper.GetString("keys.p12Dir")
		viper.SetDefault("keys.keysDir", "keys")
		*keysDir = viper.GetString("keys.keysDir")
		viper.SetDefault("keys.certDir", "certs")
		*certDir = viper.GetString("keys.certDir")
		*casePW = viper.GetString("keys.casePW")
		if casePW == nil {
			log.Fatal("Case password not configured!")
		}

		// unmarshall p12 filename-pw array
		var p12 p12Slc
		if err := viper.UnmarshalKey("keys.p12PWs", &p12); err != nil {
			log.Fatal("Failed to unmarshall p12 passwords: ", err)
		}

		// form p12 paths
		for i, p := range p12 {
			p12[i].Filename = filepath.Join(*p12Dir, p.Filename)
		}

		getkeys.GetKeys(p12, *casePW, *keysDir, *certDir)
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
