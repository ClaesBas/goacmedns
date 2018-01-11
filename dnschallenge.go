package main

import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

var dnsChallengeString string

var serveUDP *dns.Server
var serveTCP *dns.Server

func appendAnswer(m *dns.Msg, answer string) {
	rr, err := dns.NewRR(answer)
	if err == nil {
		m.Answer = append(m.Answer, rr)
	} else {
		log.Fatal("DNS-string for answer corrupt!? ,", err)
	}
}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeTXT:
			if verbose {
				log.Printf("TXT query for %s\n", q.Name)
			}
			appendAnswer(m, fmt.Sprintf("%s 60 IN TXT %s", q.Name, dnsChallengeString))

			// case dns.TypeSOA:
			// 	if verbose {
			// 		log.Printf("SOA query for %s\n", q.Name)
			// 		//dns.SOA
			// 	}
			// case dns.TypeNS:
			// 	if verbose {
			// 		log.Printf("NS query for %s\n", q.Name)
			// 	}
			// 	appendAnswer(m, fmt.Sprintf("%s 60 IN NS %s", q.Name, hostName))
			// case dns.TypeANY:
			// 	if verbose {
			// 		log.Printf("ANY query for %s\n", q.Name)
			// 	}
			// 	appendAnswer(m, fmt.Sprintf("%s 60 IN NS %s", q.Name, hostName))
		}
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}
	w.WriteMsg(m)
	if debug {
		log.Println("DNS-answer: " + m.String())
	}
}

func closeDNSServer() {
	serveUDP.Shutdown()
	serveTCP.Shutdown()
}

func serveDNSChallenge(addr, domainName, challenge string) {
	dnsChallengeString = "\"" + challenge + "\""
	dns.HandleFunc("_acme-challenge."+domainName+".", handleDNSRequest)

	serverTimeout := time.NewTimer(time.Second * time.Duration(timeOut))
	go func() {
		<-serverTimeout.C
		closeDNSServer()
		log.Fatalf("Max time for challenge requests expired (%ds) from LE expired!", timeOut)
	}()

	if verbose {
		log.Println("DNS server starting")
	}
	go func() {
		serveUDP = &dns.Server{Addr: addr, Net: "udp"}
		err := serveUDP.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		serveTCP = &dns.Server{Addr: addr, Net: "tcp"}
		err := serveTCP.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}()
	if debug {
		log.Println("DNS server started")
	}
}
