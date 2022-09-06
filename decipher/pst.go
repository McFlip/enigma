// processes 1 pst
package main

import (
	"fmt"

	pst "github.com/mooijtech/go-pst/v4/pkg"
)

func processPST(file string, outDir string, certKeyPairs []certKeyPair) error {
	pstFile, err := pst.NewFromFile(file)

	if err != nil {
		fmt.Printf("Failed to create PST file: %s\n", err)
		return err
	}

	defer func() {
		err := pstFile.Close()

		if err != nil {
			fmt.Printf("Failed to close PST file: %s", err)
		}
	}()

	// fmt.Printf("Parsing file...")

	isValidSignature, err := pstFile.IsValidSignature()

	if err != nil {
		fmt.Printf("Failed to read signature: %s\n", err)
		return err
	}

	if !isValidSignature {
		fmt.Printf("Invalid file signature.\n")
		return err
	}

	formatType, err := pstFile.GetFormatType()

	if err != nil {
		fmt.Printf("Failed to get format type: %s\n", err)
		return err
	}

	// fmt.Printf("Format type: %s\n", formatType)

	encryptionType, err := pstFile.GetEncryptionType(formatType)

	if err != nil {
		fmt.Printf("Failed to get encryption type: %s\n", err)
		return err
	}

	// fmt.Printf("Encryption type: %s\n", encryptionType)

	// fmt.Printf("Initializing B-Trees...\n")

	err = pstFile.InitializeBTrees(formatType)

	if err != nil {
		fmt.Printf("Failed to initialize node and block b-tree.\n")
		return err
	}

	rootFolder, err := pstFile.GetRootFolder(formatType, encryptionType)

	if err != nil {
		fmt.Printf("Failed to get root folder: %s\n", err)
		return err
	}

	// numSubFolders tracks how far we have decended and how many goroutines we must wait on
	// cSub signals decending 1 level; lauching goroutine
	// cDone signals ascending back 1 level; goroutine is done
	// cErr is for error signaling
	cSub := make(chan string)
	cDone := make(chan string)
	cErr := make(chan string)
	numSubFolders := 0
	go GetSubFolders(pstFile, rootFolder, formatType, encryptionType, file, outDir, certKeyPairs, cSub, cDone, cErr)

	for {
		select {
		case dive := <-cSub:
			numSubFolders++
			fmt.Println(dive)
		case done := <-cDone:
			numSubFolders--
			fmt.Println(done)
		case err := <-cErr:
			fmt.Println(err)
			// case <-cErr:
			// 	fmt.Println("Fubar")
		}
		if numSubFolders < 0 {
			break
		}
	}

	return nil
}
