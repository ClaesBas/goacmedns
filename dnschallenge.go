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
		if q.Qtype == dns.TypeTXT {
			logVerbose("TXT query for " + q.Name)
			appendAnswer(m, fmt.Sprintf("%s %d IN TXT %s", q.Name, timeOut, dnsChallengeString))
		}
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	if r.Opcode == dns.OpcodeQuery {
		parseQuery(m)
	}
	w.WriteMsg(m)
	logDebug("DNS-answer: " + m.String())
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

	logVerbose("DNS server starting")
	go func() {
		serveUDP = &dns.Server{Addr: addr, Net: "udp"}
		if err := serveUDP.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		serveTCP = &dns.Server{Addr: addr, Net: "tcp"}
		if err := serveTCP.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	logDebug("DNS server started")
}
