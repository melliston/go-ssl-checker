package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"time"
)

func main() {
	domain := "thegrandfathersteakhouse.uk"
	conn, err := tls.Dial("tcp", domain+":443", nil)
	if err != nil {
		log.Fatalf("server does not support SSL certificate: %s", err.Error())
	}

	err = conn.VerifyHostname(domain)
	if err != nil {
		log.Fatalf("hostname does not match the SSL certificate: %s", err.Error())
	}

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	fmt.Printf("Domain: %s\nSSL issuer: %s\nExpiry: %v\n\n", domain, conn.ConnectionState().PeerCertificates[0].Issuer, expiry.Format(time.RFC850))

}
