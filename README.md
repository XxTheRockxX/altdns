# Altdns - Updated Version - Subdomain discovery through alterations and permutations

Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging) as well as takes in a list of subdomains that you know of.

From these two lists that are provided as input to altdns, the tool then generates a _massive_ output of "altered" or "mutated" potential subdomains that could be present. It allows the output to be piped to your favorite DNS bruteforcing tool without consuming a large amount of memory. 

Altdns works best with large datasets. Having an initial dataset of 200 or more subdomains should churn out some valid subdomains via the alterations generated.

Further information on attack methodology and this tool release can be found here: https://docs.google.com/presentation/d/1PCnjzCeklOeGMoWiE2IUzlRGOBxNp8K5hLQuvBNzrFY/

# Installation

Python 3:

# Usage

`# python3 altdns -i subdomains.txt -w words.txt -t 100 -l 1G | puredns resolve`
- `-i` subdomains.txt` contains the known subdomains for an organization
- `-w` words.txt` is your list of words that you'd like to permute your current subdomains with (i.e. `admin`, `staging`, `dev`, `qa`) - one word per line
- `-t` how many threads the resolver will use simultaneously
- `-l` 1G How many bytes to output

# Screenshots

<img src="https://i.imgur.com/fkfZqkl.png" width="600px"/>

<img src="https://i.imgur.com/Jyfue26.png" width="600px"/>

# Show some love

If this tool was useful at all to you during DNS recon stages - we'd love to know. Any suggestions or ideas for this tool are welcome - just tweet [@infosec_au](https://twitter.com/infosec_au) or [@nnwakelam](https://twitter.com/nnwakelam) and we'll work on it.
