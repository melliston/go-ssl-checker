package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"
)

type SSLRecord struct {
	Domain       string
	Valid        bool
	Expiry       time.Time
	Certificates []*x509.Certificate
	Notes        string
}

func main() {
	// TODO Handle better input eg command line, csv file, also config output too
	separator := ","
	domains := []string{"http://aptestshop.co.uk"}
	records := make([]SSLRecord, 0)

	for _, domain := range domains {
		ssl := Validate(domain)
		records = append(records, ssl)
	}

	log.Printf("Domain%sValid%sExpiry%sSSL Issuer%sNotes", separator, separator, separator, separator)
	for _, r := range records {
		issuer := ""
		if len(r.Certificates) > 0 {
			issuer = r.Certificates[0].Issuer.String()
		}
		log.Printf("%s%s%t%s%s%s%s%s%s\n", r.Domain, separator, r.Valid, separator, r.Expiry.Format(time.RFC850), separator, issuer, separator, r.Notes)
	}

}

func Validate(domain string) SSLRecord {
	ssl := SSLRecord{
		Domain: cleanseDomain(domain),
	}

	valid := true

	conn, err := tls.Dial("tcp", ssl.Domain+":443", nil)
	if err != nil {
		ssl.Notes += fmt.Sprintf("server does not support SSL certificate: %s\n", err.Error())
		valid = false
		return ssl
	}

	err = conn.VerifyHostname(ssl.Domain)
	if err != nil {
		ssl.Notes += fmt.Sprintf("hostname does not match the SSL certificate: %s\n", err.Error())
		valid = false
		return ssl
	}
	ssl.Certificates = conn.ConnectionState().PeerCertificates
	expiry := ssl.Certificates[0].NotAfter
	if time.Now().After(expiry) {
		ssl.Notes += fmt.Sprintf("SSL certificate has expired: %v\n", expiry.Format(time.RFC850))
		valid = false
	}

	if valid {
		ssl.Valid = true
	}

	conn.Close()

	return ssl
}

func cleanseDomain(domain string) string {
	domain = strings.Replace(domain, "https://", "", -1)
	domain = strings.Replace(domain, "http://", "", -1)
	domain = strings.Replace(domain, "www.", "", -1)
	domain = strings.Replace(domain, "/", "", -1)
	return domain
}
