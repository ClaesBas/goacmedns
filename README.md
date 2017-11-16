# goacmedns
Handle Let's Encrypt DNS challenges

It's possible to delegate the subdomain `_acme-challenge` and handle LE (Let's Encrypt) DNS-challenges with one specific DNS-server (instead of waiting for "sync"). This also makes it possible to have most of the DNS-functionality "outsourced".

Initial version of this program uses a local TinyDNS-server to respond with the text-record for the LE DNS-challange.
Future plan is to "embed" DNS-funcionality and make this application standalone (credits for this idea: Peter Hellberg).

Needed parameters (now hardcoded in source..):
* Domain for the cert (think of the upcoming support for wildcard certs)
* Email address (for "Cert-admin")
* Key size in number of bits for the cert (default could be 2048)
* Path including filename for LE private key (gets registered at LE as an "account")
* Path including filename for the cert we want to create
* Path including filename for the private key of the cert we want to create
* Delay in seconds between creation of text-record and the "client.Accept()" call
* URL of the LE API (there is a "staging" also, for test)

DNS related future parameters needed:
* IP to listen on
* FQDN for the "DNS-service"
* Port to listen on (default 53, makes it possible to run without root if a firewall redirects it from something >1024)

How to delegate a subdomain in DNS:
* TinyDNS:
* BIND:
* Other DNS's and "providers"
