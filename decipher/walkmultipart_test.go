package main

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/youmark/pkcs8"
)

func TestPlainMsgBody(t *testing.T) {
	const expected = "This is just a plain single-part body."
	msg := []byte(expected)
	certKeyPairs := []certKeyPair{}
	certBytes, err := os.ReadFile("../testdata/certIn/12c3905b55296e401270c0ceb18b5ba660db9a1f.cert")
	if err != nil {
		t.Error(err)
	}
	keyBytes, err := os.ReadFile("../testdata/keyIn/12c3905b55296e401270c0ceb18b5ba660db9a1f.key")
	if err != nil {
		t.Error(err)
	}
	myCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Error(err)
	}
	myKey, err := pkcs8.ParsePKCS8PrivateKey(keyBytes, []byte("MrGlitter"))
	if err != nil {
		t.Error(err)
	}
	myCertKeyPair := certKeyPair{myCert, myKey}
	certKeyPairs = append(certKeyPairs, myCertKeyPair)
	actual, err := walkMultipart(msg, certKeyPairs)
	if err != nil {
		t.Error(err)
	}
	if string(actual) != expected {
		t.Errorf("Expected  %s, but got %s", expected, actual)
	}
}
