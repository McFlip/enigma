// deciphers byteslice using a cert/key from the given keyring
package decipher

import (
	"errors"

	"go.mozilla.org/pkcs7"
)

func decipher(attachBytes []byte, certKeyPairs []certKeyPair) ([]byte, error) {
	p7m, err := pkcs7.Parse(attachBytes)
	if err != nil {
		return nil, err
	}
	var pt []byte
	for i, certKeyPair := range certKeyPairs {
		pt, err = p7m.Decrypt(certKeyPair.cert, certKeyPair.privKey)
		// opague-signed case
		if errors.Is(err, pkcs7.ErrNotEncryptedContent) {
			return p7m.Content, nil
		}
		if err != nil {
			if i == len(certKeyPairs)-1 {
				return nil, err
			}
		}
	}
	return pt, nil
}
