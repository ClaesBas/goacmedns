# goacmedns

Handle Let's Encrypt DNS challenges (not in production quality yet... or maybe)

It's possible to delegate the subdomain `_acme-challenge` and handle LE (Let's Encrypt) DNS-challenges with one specific DNS-server (this utility/program, instead of waiting for "delegation" to many DNS servers before the challenge could be fulfilled). This also makes it possible to have most of the (other) DNS-functionality "outsourced" anywhere.

The plan with this concept is to be able manage all your domain certs in one place with this program and LE's upcoming wildcard certs is only going to work with the DNS-challenge (what I've read).

Initial version of this program uses a local TinyDNS-server to respond with the text-record for the LE DNS-challange.
Future plan is to "embed" DNS-funcionality and make this application standalone (credit for this embed-idea: @PeterHellberg).

## Usage

```text
Usage of ./goacmedns:
  -D DEBUG (bool)
        Short for DEBUG (bool)
  -DEBUG
        Debug & "Staging" mode
  -d domain
        Short for: domain
  -domain string
        (*) Domain to request the certificate for
  -e email
        Short for: email
  -email string
        Email address used for the ACME-registration
  -k keysize
        Short for: keysize (default 2048)
  -keysize int
        Keysize of requested certificate (default 2048)
  -l listen
        Short for: listen (default "127.0.0.1:53053")
  -listen string
        Listen address for embedded DNS-server (default "127.0.0.1:53053")
  -p path
        Short for: path
  -path string
        Working directory path (default ".")
  -t timeout
        Short for: timeout (default 90)
  -timeout int
        Timeout in seconds for DNS requests (from LE) (default 60)
  -v verbose (bool)
        Short for verbose (bool)
  -verbose
        Verbose mode (some extra output)
```

The domain (-d) is the only mandatory parameter.

If email parameter id omitted, it's going to be hostmaster@domain.xx (ie with the domain parameters two rightmost parts)

* Port to listen on (default 53, makes it possible to run without root if a firewall redirects it from something >1024)

## How to delegate a subdomain in DNS

* TinyDNS

Create an entry like `&_acme-challenge.domain.com::dnsserver.somedomain.com:600` in your config. Where `domain.com`is the domain to create cert for, `dnsserver.somedomain.com` is FQDN for the host running goacmedns and `600` is the TTL for this record.

* BIND

* Other DNS's and "providers"

## Tips

Redirect port 53 on incoming interface to for example 53053 on localhost, and you could run goacmedns as an ordinary user.

Call goacmedns from a script which you put in a crontab job.

## Examples of usage

./goacmedns -d somedomain.com

./goacmedns -d somedomain.com -D

./goacmedns -d somedomain.com -v

./goacmedns -d somedomain.com -l 127.0.0.1:53053

./goacmedns -d somedomain.com -p /etc/ssl/private

## Todo

Comment the examples above (and maybe some more)

Implement LE 2.0 API and Wildcard certs when it's released

Clean up the "code"

Some testing (and maybe some go tests...)

Get some (more) feedback...

Check out keysize possibilitys

Firewall config examples (for iptables, pf, ipf ...)

DNS delegation examples for more than TinyDNS

Should maybe "staging" have it's own parameter (staging & S or s)?

Test if [CAA records](https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization) speeds up the "process"

Eventually add dependencies with dep (just now, it's only golang.org/x/crypto/acme and github.com/miekg/dns)

## Known problems

If listen's IP not defined (like ":53053") the DNS service does not send answers from localhost

## Credits

Alex @x1ddos, for his [snippet](https://github.com/golang/go/issues/17263#issuecomment-253149953)

Peter Hellberg @PeterHellberg, for the "pro tip" of creating an embedded DNS server in GO (with a [DNS library in Go](https://github.com/miekg/dns) by @miekg)

Miek Gieben @miekg, for the [DNS library in Go](https://github.com/miekg/dns)

:trollface:
