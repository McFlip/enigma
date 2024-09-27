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
	"bytes"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/McFlip/enigma/cmd/decipher"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	ct, pt        *string
	eml, parallel *bool
)

// decipherCmd represents the decipher command
var decipherCmd = &cobra.Command{
	Use:   "decipher",
	Short: "Decipher encrypted emails in a batch of PST archives",
	Long: `Decipher encrypted emails in a batch of PST archives.

  Ensure you have configured the case and extracted all of your keys 1st.
  Successfully deciphered emails will output RFC822 format emails as '.eml' files`,
	Run: func(cmd *cobra.Command, args []string) {
		viper.SetDefault("decipher.ct", "ct")
		*ct = viper.GetString("decipher.ct")
		viper.SetDefault("decipher.pt", "pt")
		*pt = viper.GetString("decipher.pt")
		viper.SetDefault("keys.keysDir", "keys")
		*keysDir = viper.GetString("keys.keysDir")
		viper.SetDefault("keys.certDir", "certs")
		*certDir = viper.GetString("keys.certDir")
		*casePW = viper.GetString("keys.casePW")
		if casePW == nil || *casePW == "" {
			log.Fatal("Case password not configured!")
		}
		viper.SetDefault("decipher.eml", false)
		*eml = viper.GetBool("decipher.eml")
		// https://github.com/pst-format/libpst/issues/7
		// libpst v0.6.76(current release) has race condition.
		// bug fixed in git main source
		// flag to allow parallel jobs for readpst if using built-from-source version
		viper.SetDefault("decipher.parallel", true)
		*parallel = viper.GetBool("decipher.parallel")

		// for each custodian, unpack each pst and decipher
		const unpack = "/mnt/ramdisk/unpack"
		var outDir, numProcs string

		// set readpst to use 1 job per CPU core. 0 disables parallel processing.
		numProcs = "0"
		if *parallel {
			nproc := exec.Command("nproc")
			var out bytes.Buffer
			nproc.Stdout = &out
			err := nproc.Run()
			if err != nil {
				log.Fatal(err)
			}
			numProcs = out.String()
		}

		filepath.Walk(*ct, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				log.Fatal(err)
			}
			readpstArgs := []string{
				"-D", "-o", unpack, "-t", "e", "-e", "-j", numProcs,
			}
			if info.IsDir() {
				base := filepath.Base(path)
				if base == *ct {
					return nil
				}
				outDir = filepath.Join(*pt, base)
				err := os.Mkdir(outDir, 0755)
				if err != nil {
					log.Fatal(
						"Error making custodian subfolder in pt outpath ",
						outDir,
						" err: ",
						err,
					)
				}
				err = os.Mkdir(filepath.Join(outDir, "logs"), 0755)
				if err != nil {
					log.Fatal(
						"Error making custodian log subfolder in pt outpath ",
						outDir,
						" err: ",
						err,
					)
				}
			} else {
				if *eml {
					log.Println("Processing .eml files")
					decipher.Decipher(*ct, *certDir, *keysDir, *casePW, outDir)
					return filepath.SkipDir
				}
				if filepath.Ext(info.Name()) != ".pst" {
					log.Fatal("ciphertext input must be pst files")
				}
				err := removeContents(unpack)
				if err != nil {
					log.Fatal("Error cleaning out unpack dir ", err)
				}
				readpstArgs = append(readpstArgs, path)
				log.Println("unpacking PST file")
				readpst := exec.Command("readpst", readpstArgs...)
				err = readpst.Run()
				if err != nil {
					log.Fatal("Error in readpst: ", err)
				}
				log.Println("finished unpacking")
				log.Println("Processing ", info.Name(), " ...stand by...")
				decipher.Decipher(unpack, *certDir, *keysDir, *casePW, outDir)
				err = removeContents(unpack)
				if err != nil {
					log.Fatal("Error cleaning out unpack dir ", err)
				}
			}
			return nil
		})
		log.Println("DONE!")
	},
}

func init() {
	rootCmd.AddCommand(decipherCmd)
	ct = decipherCmd.PersistentFlags().
		String("ct", "", "Dir containing ciphertext emails. Make a subfolder for each custodian under this.")
	viper.BindPFlag("decipher.ct", decipherCmd.PersistentFlags().Lookup("ct"))
	pt = decipherCmd.PersistentFlags().
		String("pt", "", "Dir for output plaintext. There will be a subfolder for each custodian and a log folder under that.")
	viper.BindPFlag("decipher.pt", decipherCmd.PersistentFlags().Lookup("pt"))
	keysDir = decipherCmd.PersistentFlags().String("keysDir", "", "keys for decryption")
	viper.BindPFlag("keys.keysDir", decipherCmd.PersistentFlags().Lookup("keysDir"))
	certDir = decipherCmd.PersistentFlags().String("certDir", "", "certificates for decryption")
	viper.BindPFlag("keys.certDir", decipherCmd.PersistentFlags().Lookup("certDir"))
	eml = decipherCmd.PersistentFlags().Bool("eml", true, "switches input from PST to eml")
	viper.BindPFlag("decipher.eml", decipherCmd.PersistentFlags().Lookup("eml"))
	parallel = decipherCmd.PersistentFlags().
		Bool("parallel", true, "enable parallel processing for readpst")
	viper.BindPFlag("decipher.parallel", decipherCmd.PersistentFlags().Lookup("parallel"))
}

func removeContents(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}
