# dnscheck
DNS checker written in GO

### why?

I needed a tool to clean fast a large list of subdomains filtering NXDOMAINs and WildCards.

### Usage

The usage is pretty simple, just run dnscheck again a list using the same options as dmut.

(You don't know what dmut is?, take a look! (https://github.com/bp0lr/dmut)

`
cat domains.txt | dnscheck --show-stats --dnsFile /root/.dmut/top20.txt -w 50 -o results.txt
`
