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

// TODO: filter headers and do re-write within boundaries
func walkMultipart(attachBytes []byte, certKeyPairs []certKeyPair) ([]byte, error) {
	pt := []byte{}
	msg, err := mail.ReadMessage(bytes.NewReader(attachBytes))
	if err != nil {
		// If it's not a mail msg then just return back the input
		return attachBytes, nil
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	fmt.Println("$$$")
	fmt.Println(mediaType)
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
		pt, err = decipher(dst, certKeyPairs)
		if err != nil {
			return nil, err
		}
		ptChild, err := walkMultipart(pt, certKeyPairs)
		if err != nil {
			return nil, err
		}
		if len(ptChild) == 0 {
			return pt, nil
		}
		return ptChild, nil
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		slurp, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}
		fmt.Println("!!!")
		fmt.Println(p.Header)
		fmt.Println("!!!")
		if strings.Contains(p.Header.Get("Content-Type"), "message/rfc822") {
			return walkMultipart(slurp, certKeyPairs)
		}
	}
	return pt, nil
}
