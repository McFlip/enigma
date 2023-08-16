// recursive func for handling nested encrypted emails
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

func walkMultipart(attachBytes []byte, certKeyPairs []certKeyPair) ([]byte, error) {
	pt := []byte{}
	msg, err := mail.ReadMessage(bytes.NewReader(attachBytes))
	if err != nil {
		// If it's not a mail msg then just return back the input
		return attachBytes, nil
	}
	for key, values := range msg.Header {
		/*
			Filter out the following headers normally found in encrypted msg
			Content-Transfer-Encoding: base64
			X-Ms-Has-Attach: yes
			Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
			Content-Disposition: attachment; filename="smime.p7m"
		*/
		if key == "Content-Type" && strings.Contains(strings.Join(values, " "), "smime.p7m") {
			continue
		}
		if key == "Content-Transfer-Encoding" || key == "X-Ms-Has-Attach" || key == "Content-Disposition" {
			continue
		}
		// if key == "Content-Disposition" && strings.Contains(strings.Join(values, " "), "smime.p7m") {
		// 	continue
		// }
		headerElemnent := fmt.Sprintf("%s: %s\n", key, strings.Join(values, "\n    "))
		pt = append(pt, headerElemnent...)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	// can be application/pkcs7-signature, but can also be x-application/... or application/x-pkcs7-sig...
	if strings.Contains(mediaType, "pkcs7") {
		src, err := io.ReadAll(msg.Body)
		if err != nil {
			log.Fatal(err)
		}
		dst := make([]byte, len(src))
		n, err := base64.StdEncoding.Decode(dst, src)
		if err != nil {
			log.Fatal(err)
		}
		dst = dst[:n]
		childPt, err := decipher(dst, certKeyPairs)
		if err != nil {
			return nil, err
		}
		childPt, err = walkMultipart(childPt, certKeyPairs)
		if err != nil {
			return nil, err
		}
		pt = append(pt, childPt...)
		return pt, nil
	}
	boundary := params["boundary"]
	mr := multipart.NewReader(msg.Body, boundary)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			pt = append(pt, fmt.Sprintf("\n--%s--\n", boundary)...)
			break
		}
		if err != nil {
			return nil, err
		}
		pt = append(pt, fmt.Sprintf("\n--%s\n", boundary)...)
		slurp, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}
		pHeader := []byte{}
		for key, values := range p.Header {
			pHeadElement := fmt.Sprintf("%s: %s\n", key, strings.Join(values, "\n    "))
			pHeader = append(pHeader, []byte(pHeadElement)...)
		}
		pt = append(pt, pHeader...)
		pt = append(pt, "\n"...)
		if strings.Contains(p.Header.Get("Content-Type"), "message/rfc822") {
			child, err := walkMultipart(slurp, certKeyPairs)
			if err != nil {
				return nil, err
			}
			pt = append(pt, child...)
		} else {
			pt = append(pt, slurp...)
		}
	}
	return pt, nil
}
