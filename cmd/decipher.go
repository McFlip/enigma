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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ct, pt *string

// decipherCmd represents the decipher command
var decipherCmd = &cobra.Command{
	Use:   "decipher",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("decipher called")
		viper.SetDefault("decipher.ct", "ct")
		*ct = viper.GetString("decipher.ct")
		fmt.Println("ct: ", *ct)
		viper.SetDefault("decipher.pt", "pt")
		*pt = viper.GetString("decipher.pt")
		fmt.Println("pt: ", *pt)
		viper.SetDefault("keys.keysDir", "keys")
		*keysDir = viper.GetString("keys.keysDir")
		fmt.Println("keysDir: ", *keysDir)
		viper.SetDefault("keys.certDir", "certs")
		*certDir = viper.GetString("keys.certDir")
		fmt.Println("certDir: ", *certDir)
		*casePW = viper.GetString("keys.casePW")
		if casePW == nil || *casePW == "" {
			log.Fatal("Case password not configured!")
		}
		fmt.Println("pw: ", *casePW)
	},
}

func init() {
	rootCmd.AddCommand(decipherCmd)
	ct = decipherCmd.PersistentFlags().
		String("ct", "", "Dir containing ciphertext emails. Make a subfolder for each custodian under this.")
	viper.BindPFlag("decipher.ct", decipherCmd.PersistentFlags().Lookup("ct"))
	pt = decipherCmd.PersistentFlags().
		String("pt", "", "Dir for output plaintext. There will be a subfolder for each custodian and a log folder under that.")
	keysDir = decipherCmd.PersistentFlags().String("keysDir", "", "keys for decryption")
	viper.BindPFlag("decipher.pt", decipherCmd.PersistentFlags().Lookup("pt"))
}
