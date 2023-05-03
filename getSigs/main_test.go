package main

import "testing"

func TestProcessPST(t *testing.T) {
	testFile := "../testdata/pstIn/TEST.pst"
	c := make(chan string)
	expected := "Name: LAST, FIRST MIDDLE\nEmail: sender@local\nEDIPI: 12345678\nPrinciple Name: 12345678@mil\nSerial: 12c3905b55296e401270c0ceb18b5ba660db9a1f\nIssuer: CN=LAST.FIRST.MIDDLE.12345678,OU=Forensics,O=USACE,L=Jacksonville,ST=FL,C=US,1.2.840.113549.1.9.1=#0c1d47726164792e432e44656e746f6e4075736163652e61726d792e6d696c\nCertificate Authority: LAST.FIRST.MIDDLE.12345678\nNot Before: 2020-04-17 15:56:38 +0000 UTC\nNot After: 2021-04-17 15:56:38 +0000 UTC"
	go processPST(testFile, c)
	actual := <-c

	if actual != expected {
		t.Errorf("Expected\n%s\n but got\n%s", expected, actual)
	}

}
