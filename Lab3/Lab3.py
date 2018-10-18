#!/usr/bin/env python3

import socket
import sys
import requests

if __name__ == '__main__':
    domain = sys.argv[1]
    if sys.argv[2] == '-d':
        subdomain_dict = []
        with open("wordlist_1.txt") as f: 
            for line in f:
                subdomain_dict.append(line.strip())
        subdomain_found = []
        for sub in subdomain_dict:
            subdomain = sub + "." + domain
            try:
                addr = socket.gethostbyname(subdomain)
                print({addr : subdomain})
            except:
                pass
    elif sys.argv[2] == '-s':
        api = "28f77bceeda1119651e9645f31a955223584873f52e8141425de5a1378113c71"
        res = requests.get("https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + api + "&domain=" + domain)
        subdomain_found = res.json()["subdomains"]
        for subdomain in subdomain_found:
            try:
                addr = socket.gethostbyname(subdomain)
                print({addr : subdomain})
            except:
                pass
    else:
        print("-d: Dictionary search")
        print("-s: VirusTotal search")
