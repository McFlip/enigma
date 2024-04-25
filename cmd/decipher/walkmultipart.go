// recursive func for handling nested encrypted emails
package decipher

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
)

func walkMultipart(attachBytes []byte, certKeyPairs []certKeyPair, foundCT *bool) ([]byte, error) {
	// DEBUG
	// fmt.Printf(
	// 	"--BEGIN walkMultipart input bytes--\n%s--END walkMultipart input bytes--\n",
	// 	attachBytes,
	// )
	attachStr := string(attachBytes)
	pt := []byte{}
	// Check if this is an encrypted msg and needs to be unwrapped
	// If this is encrypted there will be only one attachment of pkcs7 content-type and will NOT contain an rfc822 msg
	// isSigned checks the smime-type
	envelopedRe := regexp.MustCompile(`filename\*?=.*smime\.p7m"?`)
	rfc822Re := regexp.MustCompile("message/rfc822")
	hasSmime := envelopedRe.MatchString(attachStr)
	signedRegex := regexp.MustCompile(`smime-type=signed-data`)
	isSigned := signedRegex.Match(attachBytes)
	if isSigned || !hasSmime {
		return attachBytes, nil
	}
	hasRfc822 := rfc822Re.MatchString(attachStr)
	unwrapEnvelope := hasSmime && !hasRfc822

	msg, err := mail.ReadMessage(bytes.NewReader(attachBytes))
	if err != nil {
		return attachBytes, err
	}
	for key, values := range msg.Header {
		// Filter out the following message headers normally found in encrypted msg
		// X-Ms-Has-Attach: yes
		// Content-Type: multipart/mixed; boundary="--boundary-LibPST-iamunique-[GUID]_-_-"
		// Filter out the following part headers for SMIME attachment
		// Content-Transfer-Encoding: base64
		// Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
		// Content-Disposition: attachment; filename="smime.p7m"
		if unwrapEnvelope &&
			(key == "Content-Transfer-Encoding" || key == "X-Ms-Has-Attach" || key == "Content-Disposition" || key == "Content-Type") {
			continue
		}
		headerElemnent := fmt.Sprintf("%s: %s\n", key, strings.Join(values, "\n    "))
		pt = append(pt, headerElemnent...)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if !strings.Contains(mediaType, "multipart") {
		return nil, errors.New(fmt.Sprint("wrong media type: ", mediaType))
	}
	boundary := params["boundary"]
	mr := multipart.NewReader(msg.Body, boundary)
	// emptyBoundary := errors.New("multipart: boundary is empty")
	for {
		p, err := mr.NextPart()
		// if errors.Is(err, emptyBoundary) {
		// 	// DEBUG
		// 	log.Fatal("EMPTY BOUNDARY")
		// }
		if err == io.EOF {
			if !unwrapEnvelope {
				pt = append(pt, fmt.Sprintf("\n--%s--\n", boundary)...)
			}
			break
		}
		if err != nil {
			return nil, err
		}

		if !unwrapEnvelope {
			pt = append(pt, fmt.Sprintf("\n--%s\n", boundary)...)
		}
		slurp, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}

		pContentType := p.Header.Get("Content-Type")

		// check for nested msg in a msg
		if rfc822Re.MatchString(pContentType) {
			childPt, err := walkMultipart(slurp, certKeyPairs, foundCT)
			if err != nil {
				return nil, err
			}
			pt = append(pt, "Content-Type: message/rfc822\n\n"...)
			pt = append(pt, childPt...)
			continue
		}

		isSigned := signedRegex.Match(slurp)
		if strings.Contains(pContentType, "pkcs7") && !isSigned {
			*foundCT = true
			// TODO: decode using PEM decoder instead of doing manually
			dst := make([]byte, len(slurp))
			n, err := base64.StdEncoding.Decode(dst, slurp)
			if err != nil {
				log.Fatal(err)
			}
			dst = dst[:n]
			childPt, err := decipher(dst, certKeyPairs)
			if err != nil {
				return nil, err
			}
			childPt, err = walkMultipart(childPt, certKeyPairs, foundCT)
			if err != nil {
				return nil, err
			}
			pt = append(pt, childPt...)
		} else {
			pHeader := []byte{}
			for key, values := range p.Header {
				pHeadElement := fmt.Sprintf("%s: %s\n", key, strings.Join(values, "\n    "))
				pHeader = append(pHeader, []byte(pHeadElement)...)
			}
			pt = append(pt, pHeader...)
			pt = append(pt, "\n"...)
			pt = append(pt, slurp...)
		}
	}
	return pt, nil
}
