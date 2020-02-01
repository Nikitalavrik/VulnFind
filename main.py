import nmap
import sys
import requests
from bs4 import BeautifulSoup
from vuln_class import Vuln

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

def exploit_db(href):
    exp_url = "www.exploit-db.com"
    url = href[7:href.find("&")]
    # print(url)
    headers = {
        'user-agent': 'Mozilla/5.0 (X11; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0',
        'referrer': 'https://google.com',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'Pragma': 'no-cache',
    }
    page = requests.get(url, headers=headers)
    soup = BeautifulSoup(page.content, 'html.parser')
    name = soup.find_all("h1", {"class" : "card-title"})[0].text.strip()
    cve = soup.find_all("h6", {"class" : "stats-title"})[1].text.strip()
    cve_url = soup.find_all("h6")[1].find("a").get("href")
    verf = soup.find_all("i", {"class" : "mdi-check"})[0].get("style") == "color: #96b365"
    exploit = exp_url + soup.find_all("a", {"title" : "View Raw"})[0].get("href")
    tp = soup.find_all("h6", {"class" : "stats-title"})[3].text.strip()
    return Vuln(name, href, cve, cve_url, exploit, tp, verf)

def cve_details(href):
    url = href[7:href.find("&")]
    print(url)

def srcap_vuln_info(name, product, version):
    exp_db = "www.exploit-db.com"
    cve_det = "cvedetails"
    page = requests.get('https://www.google.com/search?q='+
                 " " + name + " " + product + " " + version + " vulnerability")
    # print('https://www.google.com/search?q='+
    #              " " + name + " " + product + " " + version + " vulnerability")
    soup = BeautifulSoup(page.content, 'html.parser')
    links = soup.find_all("a")
    vulns = []
    for link in links:
        href = link.get("href")
        if exp_db in href:
            vulns.append(exploit_db(href))
        if cve_det in href:
            vulns.append(cve_details(href))
    # print(soup.find_all("a")[0].get("href"))

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