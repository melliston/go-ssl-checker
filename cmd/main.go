package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
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
	var domains []string

	var domainsArg string
	var filepathArg string
	var outputArg string

	records := make([]SSLRecord, 0)
	separator := ","

	// TODO Handle better input:
	// command line (Done),
	// csv file,
	// also config output too

	// See if reading from a csv input or just command line
	flag.StringVar(&domainsArg, "domains", "", "A single domain or a comma seperated list -domains=foo.co.uk or -domains=foo.co.uk,bar.co.uk")
	flag.StringVar(&filepathArg, "file", "", "The file path to load in and parse. Contains one domain per line")
	flag.StringVar(&outputArg, "output", "csv", "The output method. Either in column format or csv format. If only one domain is supplied then defaults to column. Options are 'csv' or 'column'")
	flag.Parse()

	if len(domainsArg) == 0 && len(filepathArg) == 0 {
		flag.Usage()
		return
	}

	if len(domainsArg) > 0 {
		domains = strings.Split(domainsArg, ",")
	} else {
		domains = readFile(filepathArg)
	}

	if len(domains) == 0 {
		log.Fatalln("No domains were specified.")
	}

	// Check that if only one domain and not specified output then set it to column for output method
	if len(domains) == 1 && outputArg != "csv" {
		outputArg = "column"
	}

	for _, domain := range domains {
		ssl := Validate(domain)
		records = append(records, ssl)
	}

	if outputArg == "csv" {
		fmt.Printf("Domain%sValid%sExpiry%sSSL Issuer%sNotes\n", separator, separator, separator, separator)
	}

	var format string
	if outputArg == "csv" {
		format = "%s%s%t%s%s%s%s%s%s\n"
	}
	if outputArg == "column" {
		format = "\n\nDomain:\t\t%s%s\nValid:\t\t%t%s\nExpiry:\t\t%s%s\nSSL Issuer:\t%s%s\nNotes:\t\t%s\n"
		separator = ""
	}
	for _, r := range records {
		issuer := ""
		var expiry time.Time
		if len(r.Certificates) > 0 {
			issuer = r.Certificates[0].Issuer.String()
			expiry = r.Certificates[0].NotAfter
		}

		fmt.Printf(format, r.Domain, separator, r.Valid, separator, expiry.Format(time.RFC1123), separator, issuer, separator, r.Notes)
	}

}

func Validate(domain string) SSLRecord {
	ssl := SSLRecord{
		Domain: cleanseDomain(domain),
	}

	conn, err := tls.Dial("tcp", ssl.Domain+":443", nil)
	if err != nil {
		ssl.Notes += fmt.Sprintf("server does not support SSL certificate: %s\n", err.Error())
		ssl.Valid = false
		return ssl
	}
	defer conn.Close()

	err = conn.VerifyHostname(ssl.Domain)
	if err != nil {
		ssl.Notes += fmt.Sprintf("hostname does not match the SSL certificate: %s\n", err.Error())
		ssl.Valid = false
		return ssl
	}
	ssl.Certificates = conn.ConnectionState().PeerCertificates
	expiry := ssl.Certificates[0].NotAfter
	if time.Now().After(expiry) {
		ssl.Notes += fmt.Sprintf("SSL certificate has expired: %v\n", expiry.Format(time.RFC850))
		ssl.Valid = false
	}

	ssl.Valid = true

	return ssl
}

func readFile(filePath string) []string {
	readFile, err := os.Open(filePath)

	if err != nil {
		fmt.Println(err)
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var domains []string

	for fileScanner.Scan() {
		domains = append(domains, fileScanner.Text())
	}

	readFile.Close()

	return domains
}

func cleanseDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.Replace(domain, "https://", "", -1)
	domain = strings.Replace(domain, "http://", "", -1)
	domain = strings.Replace(domain, "www.", "", -1)
	domain = strings.Replace(domain, "/", "", -1)
	return domain
}
