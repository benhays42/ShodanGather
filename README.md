# ShodanGather
Shodan gather is a python based Shodan (Shodan.io) tool to search for devices on the internet based on certain filters.

# Usage
```gethosts.py [-h] [-t TARGETS] [-s SEARCH] [-o OUTPUT] [-p PORT] [-honeypot HONEYPOT] [--timeout TIMEOUT]

  -t TARGETS, --targets TARGETS  Set a number of targets to find    
  -s SEARCH, --search SEARCH   Set a device search term to look for    
  -o OUTPUT, --output OUTPUT   Set a output file to write ips to    
  -p PORT, --port PORT  Set a port to look for                            
  -honeypot  Scans list of ips for a potential honeypot               
  --timeout TIMEOUT     Set a time between scans (In seconds)  
```
# Installation
```git clone https://github.com/benhays42/ShodanGather.git  
cd ShodanGather-master   
chmod +x gethosts.py     
./gethosts.py
```
