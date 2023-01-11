from scapy.all import *

import requests
import time

def get_ip(pkt):
    ip = pkt[IP].src
    if ip[:4] == "192":
        return
    req = requests.get(f'https://ipapi.co/{ip}/json').json()
    print(f"""
    IP: {req.get('ip')}
    Pais: {req.get('city')}
    Região: {req.get('region')}
    ISP: {req.get('org')}
    {'-'*20}
    """)
while True:
    sniff(filter='UDP', prn=get_ip, count=1)
    time.sleep(4)   
