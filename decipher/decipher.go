// deciphers byteslice using a cert/key from the given keyring
package main

import (
	"fmt"

	"go.mozilla.org/pkcs7"
)

func decipher(attachBytes []byte, certKeyPairs []certKeyPair) ([]byte, error) {
	// os.WriteFile("smime.p7m", attachBytes, 0666)
	p7m, err := pkcs7.Parse(attachBytes)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	fmt.Println("$$$$$$$$$$$$$$$$$$")
	var pt []byte
	for i, certKeyPair := range certKeyPairs {
		// fmt.Println(certKeyPair)
		pt, err = p7m.Decrypt(certKeyPair.cert, certKeyPair.privKey)
		if err != nil {
			fmt.Println(err)
			if i == len(certKeyPairs)-1 {
				return nil, err
			}
		}
	}
	// fmt.Println(string(pt))
	return pt, nil
}
