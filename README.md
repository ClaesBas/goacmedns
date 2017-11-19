# goacmedns
Handle Let's Encrypt DNS challenges (not in production quality yet...)

It's possible to delegate the subdomain `_acme-challenge` and handle LE (Let's Encrypt) DNS-challenges with one specific DNS-server (instead of waiting for "sync" of many DNS servers before the challenge could be fulfilled). This also makes it possible to have most of the DNS-functionality "outsourced" anywhere.

The plan with this concept is to be able manage all your domain certs in one place with this program and LE's upcoming wildcard certs is only going to work with the DNS-challenge (what I've read).

Initial version of this program uses a local TinyDNS-server to respond with the text-record for the LE DNS-challange.
Future plan is to "embed" DNS-funcionality and make this application standalone (credit for this embed-idea: @PeterHellberg).

## Needed parameters (now hardcoded in source..):
* Domain for the cert (think of the upcoming support for wildcard certs, but it's possible to use it for a specific host or subdomain)
* Email address (for "Cert-admin")
* Key size in number of bits for the cert (default could be 2048)
* Path including filename for LE private key (gets registered at LE as an "account")
* Path including filename for the cert we want to create
* Path including filename for the private key of the cert we want to create
* Delay in seconds between creation of text-record and the "client.Accept()" call (not needed with embedded DNS)
* URL of the LE API (there is a "staging" also, for test)
* Logging options (like syslog or path to a file or something)

## DNS related future parameters needed:
* IP to listen on
* FQDN for the "DNS-service"
* Port to listen on (default 53, makes it possible to run without root if a firewall redirects it from something >1024)

## How to delegate a subdomain in DNS:
* TinyDNS:  
Create an entry like `&_acme-challenge.domain.com::dnsserver.somedomain.com:60` in your config. Where `domain.com`is the domain to create cert for, `dnsserver.somedomain.com`is FQDN for the host running goacmedns (and TinyDNS until we manage to reply with "built in" DNS) and `60` is the TTL for this record.
* BIND:
* Other DNS's and "providers"

## Examples of usage:

## Credits:
Alex @x1ddos, for his snippet: https://github.com/golang/go/issues/17263#issuecomment-253149953

:trollface:
