package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"time"
)

func main() {
	separator := ","
	domains := []string{"thegrandfathersteakhouse.uk"}

	log.Printf("Domain%sValid%sExpiry%sSSL Issuer%sNotes", separator, separator, separator, separator)
	for _, domain := range domains {
		valid := true
		notes := ""
		conn, err := tls.Dial("tcp", domain+":443", nil)
		if err != nil {
			notes += fmt.Sprintf("server does not support SSL certificate: %s", err.Error())
			valid = false
		}

		err = conn.VerifyHostname(domain)
		if err != nil {
			notes += fmt.Sprintf("hostname does not match the SSL certificate: %s", err.Error())
			valid = false
		}

		expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
		if time.Now().After(expiry) {
			notes += fmt.Sprintf("SSL certificate has expired: %v", expiry.Format(time.RFC850))
			valid = false
		}

		log.Printf("%s%s%t%s%s%s%s%s%s\n", domain, separator, valid, separator, expiry.Format(time.RFC850), separator, conn.ConnectionState().PeerCertificates[0].Issuer, separator, notes)

		conn.Close()
	}

}
