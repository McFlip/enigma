// Filters out Content-Type & Content-Transfer-Encoding
//
//	headers to be replaced by headers from deciphered msg body
package main

import (
	"bytes"
	"regexp"
	"strings"
)

func filterHeaders(headers string) string {
	// null bytes in MS Outlook string encoding breaks strings funcs & regexp
	headersBS := []byte(headers)
	headersBS = bytes.ReplaceAll(headersBS, []byte{00}, []byte{})
	headers = string(headersBS)
	accumulated := ""
	currentHeader := ""
	headerList := strings.Split(headers, "\n")
	headKey := regexp.MustCompile(`^[A-Z,a-z,-]+:`)
	for _, ln := range headerList {
		// filter out the keys we don't want
		if strings.HasPrefix(ln, "Content-Type:") || strings.HasPrefix(ln, "Content-Transfer-Encoding:") {
			continue
		}
		// Keys can have values accross multiple lines, starting with a space
		// If we find a new key then we know we are done processing the previous key
		if headKey.MatchString(ln) {
			accumulated = accumulated + currentHeader
			currentHeader = ln + "\n"
		} else {
			currentHeader = currentHeader + ln + "\n"
		}
	}
	// Reached the end of the header, flush the last key-value
	accumulated = accumulated + currentHeader
	return strings.Trim(accumulated, "\r\n") + "\r\n"
}
