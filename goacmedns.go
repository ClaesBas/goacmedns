package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

//"Runtime flags"
var debug bool
var verbose bool

//DNS-server related parameters
var listen string
var timeOut int

//ACME-related
var domain string
var email string
var keySize int

var workPath string

//Other global vars..
var directoryURL string
var dnsServerRunning bool

func init() {

	flag.BoolVar(&debug, "DEBUG", false, "Debug & \"Staging\" mode")
	flag.BoolVar(&debug, "D", false, "Short for `DEBUG (bool)`")

	flag.BoolVar(&verbose, "verbose", false, "Verbose mode (some extra output)")
	flag.BoolVar(&verbose, "v", false, "Short for `verbose (bool)`")

	flag.StringVar(&listen, "listen", "127.0.0.1:53053", "Listen address for embedded DNS-server")
	flag.StringVar(&listen, "l", "127.0.0.1:53053", "Short for: `listen`")

	flag.IntVar(&keySize, "keysize", 2048, "Keysize of requested certificate")
	flag.IntVar(&keySize, "k", 2048, "Short for: `keysize`")

	flag.StringVar(&email, "email", "", "Email address used for the ACME-registration")
	flag.StringVar(&email, "e", "", "Short for: `email`")

	flag.StringVar(&domain, "domain", "", "(*) Domain to request the certificate for")
	flag.StringVar(&domain, "d", "", "Short for: `domain`")

	flag.StringVar(&workPath, "path", ".", "Working directory path")
	flag.StringVar(&workPath, "p", ".", "Short for: `path`")

	flag.IntVar(&timeOut, "timeout", 90, "Timeout in seconds for DNS requests (from LE)")
	flag.IntVar(&timeOut, "t", 90, "Short for: `timeout`")
}

func logDebug(text string) {
	if debug {
		log.Println(text)
	}
}

func logVerbose(text string) {
	if verbose {
		log.Println(text)
	}
}

func checkParameters() {

	extraError := ""
	//Maye some more "flag-checking" (setting extraError if...) !!!!!!

	if domain == "" || extraError != "" {
		if extraError == "" {
			fmt.Println("Error: you must at least define -domain (-d)")
		} else {
			fmt.Println("Error: " + extraError)
		}
		fmt.Println("See: https://github.com/ClaesBas/goacmedns")
		fmt.Print("\nUsage of " + os.Args[0] + ":\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if email == "" {
		tmpStrArr := strings.Split(domain, ".")
		var emailDomain string
		if len(tmpStrArr) > 2 {
			emailDomain = strings.Join(tmpStrArr[len(tmpStrArr)-2:], ".")
		} else {
			emailDomain = domain
		}
		email = "hostmaster@" + emailDomain
	}

	if workPath[len(workPath)-1] != "/"[0] {
		workPath += "/"
	}

	if debug {
		directoryURL = "https://acme-staging.api.letsencrypt.org/directory"
		verbose = true
	} else {
		directoryURL = "https://acme-v01.api.letsencrypt.org/directory"
	}
}

func lookupAcmeHost(urlStr string) {
	u, err := url.Parse(urlStr)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := net.LookupHost(u.Hostname()); err != nil {
		log.Fatal(err)
	}
	logDebug(u.Hostname() + " found (in DNS)")
}

func getOrCreateRSAPrivateKey(path string) (key *rsa.PrivateKey, newKey bool) {
	newKey = false
	_, err := os.Stat(path)
	if err == nil {
		keyFile, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		pemBlock, _ := pem.Decode(keyFile)
		if key, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes); err != nil {
			log.Fatal(err)
		}
	} else {
		if key, err = rsa.GenerateKey(rand.Reader, keySize); err != nil {
			log.Fatal(err)
		}
		logVerbose("New rsa-key created!")
		keydata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			},
		)
		if err = ioutil.WriteFile(path, keydata, 0600); err != nil {
			log.Fatal(err)
		}
		newKey = true
	}
	return key, newKey
}

func registerNewAcmeAccount(client *acme.Client, email string) {
	ctx := context.Background()
	initialAccount := &acme.Account{Contact: []string{"mailto:" + email}}
	acc, err := client.Register(ctx, initialAccount, acme.AcceptTOS)
	if err != nil {
		log.Fatal(err)
	}
	logDebug(fmt.Sprintf("New registered account: %+v", acc))
}

func getChallengeTokenAndAcceptChallenge(client *acme.Client, a *acme.Authorization) (string, *acme.Challenge) {
	// Find dns-01 challenge in a.Challenges.
	// Let's assume the var name is challenge
	var challengeToken = ""
	var acceptChallenge *acme.Challenge
	for _, challenge := range a.Challenges {
		if challenge.Type == "dns-01" {
			challengeToken = challenge.Token
			//challengeURI = challenge.URI
			acceptChallenge = challenge
			break
		}
	}

	tok, err := client.DNS01ChallengeRecord(challengeToken)
	if err != nil {
		log.Fatal(err)
	}
	logDebug("token=" + tok)

	return tok, acceptChallenge
}

func createCertPrivateKey() *ecdsa.PrivateKey {

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	privDer, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privDer,
		},
	)
	if ioutil.WriteFile(workPath+domain+".key", privPem, 0600) != nil {
		log.Fatal(err)
	}

	logVerbose("Private key for " + domain + " created and saved")

	return priv
}

func createCertPublicKey(priv *ecdsa.PrivateKey, client *acme.Client) {
	req := &x509.CertificateRequest{
		DNSNames: []string{domain},
		// EmailAddresses: []string{email},
	}

	// populate other fields
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, priv)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	ders, _, err := client.CreateCert(ctx, csr, 90*24*time.Hour, true)
	if err != nil {
		log.Fatal(err)
	}

	// Write the certificate bundle to disk
	cert0 := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ders[0],
		},
	)
	cert1 := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ders[1],
		},
	)
	if err = ioutil.WriteFile(workPath+domain+".crt", append(cert0, cert1...), 0600); err != nil {
		log.Fatal(err)
	}
	logVerbose("Certificate for " + domain + " created and saved")

}

func main() {

	flag.Parse()

	checkParameters()

	lookupAcmeHost(directoryURL) // Be sure that we don't timeout later due to DNS

	acmeKeyPath := workPath + domain + ".acmekey"

	acmeKey, newKey := getOrCreateRSAPrivateKey(acmeKeyPath)
	client := &acme.Client{Key: acmeKey, DirectoryURL: directoryURL}

	if newKey {
		registerNewAcmeAccount(client, email)
	}

	ctx := context.Background()

	a, err := client.Authorize(ctx, domain)
	if err != nil {
		log.Fatal(err)
	}
	logDebug("Authorization.Status=" + a.Status)

	// If Client.Key is already authorized for domain
	// Skip DNS record provisioning and go to client.CreateCert
	if a.Status != acme.StatusValid {

		tok, acceptChallenge := getChallengeTokenAndAcceptChallenge(client, a)

		//Start DNS server serving the challenge
		go serveDNSChallenge(listen, domain, tok)
		dnsServerRunning = true

		logVerbose("Send Accept-request")
		if _, err := client.Accept(ctx, acceptChallenge); err != nil {
			log.Fatal(err)
		}
		logVerbose("Wait for Authorization")
		if a, err = client.WaitAuthorization(ctx, a.URI); err != nil {
			log.Fatal(err)
		}

		if a.Status != acme.StatusValid {
			log.Fatal("domain authorization failed (" + a.Status + ")")
		}
		logVerbose("Authorization succeeded!")
	}

	priv := createCertPrivateKey()
	createCertPublicKey(priv, client)

	if dnsServerRunning {
		closeDNSServer()
		logDebug("DNS server stopped")
	}

	logDebug("-------- That's all folks! ---------")
}
