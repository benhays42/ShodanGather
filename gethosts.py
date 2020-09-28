#!/usr/bin/env python2
from __future__ import print_function
import shodan
import sys
import argparse
import requests
import json
import time


parser = argparse.ArgumentParser()
parser.add_argument("-t", "--targets", help="Set a number of targets to find", default=25, type=int)
parser.add_argument("-s", "--search", help="Set a device search term to look for", default="apache")
parser.add_argument("-o", "--output", help="Set a output file to write ips to", default=None)
parser.add_argument("-p", "--port", help="Set a port to look for", default=None)
parser.add_argument("-honeypot", help="Scan list of ips for a potential honeypot (Uses api key a lot (Warning))", default=None)
parser.add_argument("--timeout", help="Set a time between scans (In seconds)", default=0.3)
args = parser.parse_args()
NUM_OF_TARGETS = args.targets
TBUFFER = 0
SHODAN_API_KEY = "Tf4AqUDh2XHloLHSI3ObliTqrk4bk3BR"
api = shodan.Shodan(SHODAN_API_KEY)
try:
        # Search Shodan
	if args.port == None: 
        	results = api.search(args.search)
	else:
		results = api.search(args.search + " -p" + str(args.port))
	
        # Show the results
        print('Results found: {}'.format(results['total']))
        for result in results['matches']:
		if args.honeypot == None:
			honeypots = None
		else:
			time.sleep(float(args.timeout))
		if TBUFFER >= NUM_OF_TARGETS:
			break
		if args.output == None:
			if args.honeypot == None: 
                		print('IP: {}'.format(result['ip_str']))
			else:
				hpscore = requests.get("https://api.shodan.io/labs/honeyscore/" + result['ip_str'] + "?key=" + SHODAN_API_KEY).text
				print('IP: {}'.format(result['ip_str']) + "HP:" + hpscore)
		else:
			with open(str(args.output),'a+') as fo:
				if args.honeypot == None:
					fo.write(result['ip_str'])
					fo.write("\n")
				else:
					hpscore = requests.get("https://api.shodan.io/labs/honeyscore/" + result['ip_str'] + "?key=" + SHODAN_API_KEY).text
					if float(hpscore) < 0.5:
						fo.write(result['ip_str'])
						fo.write("\n")
					else:
						print("Honeypot found: " + result['ip_str'] + " hpscore: " + hpscore)

		TBUFFER = TBUFFER + 1
	print("Targets Acquired: " + str(TBUFFER)) 
	
except shodan.APIError, e:
        print('Error: {}'.format(e))

