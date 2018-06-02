import socket
from ipwhois import IPWhois
from flask import render_template


def whois(website):
    ip = socket.gethostbyname(website)
    obj = IPWhois(ip)
    results = obj.lookup_whois()
    return results
