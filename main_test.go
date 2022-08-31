package main

import "testing"

func TestProcessPST(t *testing.T) {
	testFile := "data/TEST.pst"
	c := make(chan string)
	expected := "LAST.FIRST.MIDDLE.12345678"
	go processPST(testFile, c)
	actual := <-c

	if actual != expected {
		t.Errorf("Expected  %s, but got %s", expected, actual)
	}

}
