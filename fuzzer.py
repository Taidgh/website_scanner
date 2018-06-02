import requests
from flask import Flask, session, render_template
import threading


class UrlFuzzer(threading.Thread):

    def __init__(self, website):
        threading.Thread.__init__(self)
        self.website = website
        self.count = 0
        self.results = []
        self.current = ""

    def run(self):
        for line in open('list.txt', 'r').readlines():
            l = line.strip("\n")
            self.current = self.website+l
            req = requests.get(self.website+l)
            self.count = self.count + 1
            if req.status_code == 200:
                self.results.append((l, 'OK'))
            elif req.status_code == 403:
                self.results.append((l, 'FORBIDDEN'))
            else:
                pass
