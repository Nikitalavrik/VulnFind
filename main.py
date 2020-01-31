import nmap
import sys
import requests
from bs4 import BeautifulSoup

def parse_input():
    if len(sys.argv) > 1:
        ip = sys.argv[1]
        port_range = '1-65535'
        if len(sys.argv) == 3:
            port_range = sys.argv[2]
    else:
        print("usage : python3 main.py ip port_range")
        exit(0)
    print("ip : %s port_range : %s" % (ip, port_range))
    return ip, port_range

def print_scan_info(nm, ip):
    print("Hostname : %s" % (nm[ip].hostname()))
    for protocol in nm[ip].all_protocols():
        print("~~~~~~~~~~~~")
        print("Protocol : %s" % (protocol))
        all_ports = list(nm[ip][protocol].keys())
        all_ports.sort()
        print("port\tstate\tname\t\tproduct\t\tversion")
        for port in all_ports:
            print("%s\t%s\t%s\t\t%s\t\t%s" % (port, nm[ip][protocol][port]['state'],
            nm[ip][protocol][port]['name'], nm[ip][protocol][port]['product'],
            nm[ip][protocol][port]['version']))

def srcap_vuln_info(name, product, version):
    vuln_db = "exploit-db"
    page = requests.get('https://www.google.com/search?q='+
                name + product + version + "vulnerability")
    soup = BeautifulSoup(page.content, 'html.parser')
    print(soup)

def look_up_ports(nm, ip):
    for protocol in nm[ip].all_protocols():
        all_ports = list(nm[ip][protocol].keys())
        srcap_vuln_info(nm[ip][protocol][all_ports[0]]['name'],
                        nm[ip][protocol][all_ports[0]]['product'],
                        nm[ip][protocol][all_ports[0]]['version'])


ip, port_range = parse_input()

nm = nmap.PortScanner()
nm.scan(ip, port_range)

print_scan_info(nm, ip)
look_up_ports(nm, ip)