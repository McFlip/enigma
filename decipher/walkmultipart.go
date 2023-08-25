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
	"regexp"
	"strings"
)

func walkMultipart(attachBytes []byte, certKeyPairs []certKeyPair, foundCT *bool) ([]byte, error) {
	// DEBUG
	fmt.Printf("!!!!\n%s!!!!\n", attachBytes)
	// DEBUG
	attachStr := string(attachBytes)
	pt := []byte{}
	// DEBUG: Check if this is an encrypted msg and needs to be unwrapped
	// If this is encrypted there will be only one attachment of pkcs7 content-type and will NOT contain an rfc822 msg
	envelopedRe := regexp.MustCompile(`filename="smime\.p7m"`)
	rfc822Re := regexp.MustCompile("message/rfc822")
	hasSmime := envelopedRe.MatchString(attachStr)
	hasRfc822 := rfc822Re.MatchString(attachStr)
	unwrapEnvelope := hasSmime && !hasRfc822
	// unwrapEnvelope := envelopedRe.MatchString(attachStr) && !rfc822Re.MatchString(attachStr)
	// unwrapEnvelope := envelopedRe.Match(attachBytes) && !rfc822Re.Match(attachBytes)
	msg, err := mail.ReadMessage(bytes.NewReader(attachBytes))
	if err != nil {
		// If it's not a mail msg then just return back the input
		// return attachBytes, nil
		return attachBytes, err
	}
	for key, values := range msg.Header {
		/*
			Filter out the following message headers normally found in encrypted msg
			X-Ms-Has-Attach: yes
			Content-Type: multipart/mixed; boundary="--boundary-LibPST-iamunique-[GUID]_-_-"
			Filter out the following part headers for SMIME attachment
			Content-Transfer-Encoding: base64
			Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
			Content-Disposition: attachment; filename="smime.p7m"
		*/
		// if key == "Content-Type" && strings.Contains(strings.Join(values, " "), "smime.p7m") {
		// 	continue
		// }
		if unwrapEnvelope && (key == "Content-Transfer-Encoding" || key == "X-Ms-Has-Attach" || key == "Content-Disposition" || key == "Content-Type") {
			continue
		}
		// if key == "Content-Disposition" && strings.Contains(strings.Join(values, " "), "smime.p7m") {
		// 	continue
		// }
		headerElemnent := fmt.Sprintf("%s: %s\n", key, strings.Join(values, "\n    "))
		// pt = append(pt, "debug1"...)
		pt = append(pt, headerElemnent...)
		// pt = append(pt, "debug1"...)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	// can be application/pkcs7-signature, but can also be x-application/... or application/x-pkcs7-sig...
	if strings.Contains(mediaType, "pkcs7") {
		*foundCT = true
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
		childPt, err = walkMultipart(childPt, certKeyPairs, foundCT)
		if err != nil {
			return nil, err
		}
		// pt = append(pt, "debug2"...)
		pt = append(pt, childPt...)
		// pt = append(pt, "debug2"...)
		return pt, nil
	}
	boundary := params["boundary"]
	mr := multipart.NewReader(msg.Body, boundary)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			if !(unwrapEnvelope && strings.Contains(boundary, `-LibPST-iamunique-`)) {
				// pt = append(pt, "debug3"...)
				pt = append(pt, fmt.Sprintf("\n--%s--\n", boundary)...)
				// pt = append(pt, "debug3"...)
			}
			break
		}
		if err != nil {
			return nil, err
		}
		if !(unwrapEnvelope && strings.Contains(boundary, `-LibPST-iamunique-`)) {
			// pt = append(pt, "debug4"...)
			pt = append(pt, fmt.Sprintf("\n--%s\n", boundary)...)
			// pt = append(pt, "debug4"...)
		}
		slurp, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}

		pContentType := p.Header.Get("Content-Type")
		fmt.Printf("@@@ Content-Type: %s\n", pContentType)
		if pContentType == "application/pkcs7-mime" {
			*foundCT = true
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
			// pt = append(pt, "debug7"...)
			pt = append(pt, childPt...)
			// pt = append(pt, "debug7"...)
		} else {
			pHeader := []byte{}
			for key, values := range p.Header {
				pHeadElement := fmt.Sprintf("%s: %s\n", key, strings.Join(values, "\n    "))
				// pHeader = append(pHeader, "debug5"...)
				pHeader = append(pHeader, []byte(pHeadElement)...)
				// pHeader = append(pHeader, "debug5"...)
			}
			// pt = append(pt, "debug6"...)
			pt = append(pt, pHeader...)
			pt = append(pt, "\n"...)
			// pt = append(pt, "debug6"...)
			if strings.Contains(pContentType, "message/rfc822") {
				// DEBUG: Clean up invalid headers from slurp ie ">From"
				child, err := walkMultipart(slurp, certKeyPairs, foundCT)
				if err != nil {
					return nil, err
				}
				// pt = append(pt, "debug8"...)
				pt = append(pt, child...)
				// pt = append(pt, "debug8"...)
			} else {
				// pt = append(pt, "debug9"...)
				pt = append(pt, slurp...)
				// pt = append(pt, "debug9"...)
			}
		}
	}
	return pt, nil
}
