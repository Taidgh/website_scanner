from flask import Flask, session, render_template, Response, request, jsonify
import string
import port_scan
from lookup import *
from fuzzer import *
import random
import threading
import urllib.request as urllib2

app = Flask(__name__)

task_queue = {}


@app.route('/', methods=['POST', 'GET'])
def index():
    """ Takes value from the drop down to perform the selected scan """
    if request.method == 'POST':
        website = request.form['website']
        scan_type = request.form['options']
        website = website.replace("http://", "")
        if not website.startswith('www'):
            website = 'www.' + website
        #if not check_url(website):
            #return render_template('error.html')

        if scan_type == 'fuzz':
            return fuzz_result(website)
        elif scan_type == 'whois':
            return look_up(website)
        else:
            return scan(website, scan_type)
    else:
        return render_template('indexpage.html')


@app.route('/fuzzer/nmout/<string:nid>')
def updateFuzzer(nid):
    """ returns the response to the ajax request (fuzzer) """
    data = {"valid": True}
    if str(nid) not in task_queue:
        data["valid"] = False
        return jsonify(data), 200
    if task_queue[nid].is_alive():
        data["progress"] = round(task_queue[nid].count / 0.77)
        data["current"] = task_queue[nid].current
    else:
        data["progress"] = "finished"

    return jsonify(data), 200


@app.route('/ajax/nmout/<string:nid>')
def updateNmap(nid):
    """ returns the response to the ajax request (Nmap) """
    data = {"valid": True}
    if str(nid) not in task_queue:
        data["valid"] = False
        return jsonify(data), 200
    data["progress"] = task_queue[nid].progress
    if not task_queue[nid].is_running():
        data["summary"] = task_queue[nid].summary
    return jsonify(data), 200


def scan(website, scan_type):
    """ starts a tcp/udp scan and adds it to task queue """
    key = generate_random_key()
    if scan_type == 'tcp':
        scan_type = '-sV'
    elif scan_type == 'udp':
        scan_type = '-sU'
    task_queue[key] = port_scan.start_scan(website, scan_type)
    return render_template('scanloader.html', nmap_key=key, target_site=website)


def look_up(website):
    """ return webpage with results of whois lookup """
    results = whois(website)
    return render_template('lookup.html', results=results)


def fuzz_result(website):
    """ adds the given task to the task_queue using a randomly generated unique key (as in a session)"""
    key = generate_random_key()
    if not website.startswith('http'):
        website = 'http://' + website
    thr = UrlFuzzer(website)
    thr.start()
    task_queue[key] = thr
    return render_template('loader.html', fuzz_key=key)


@app.route('/res/<string:nid>')
def res(nid):
    """ returns result of nmap scan """
    items = port_scan.ret_scan(task_queue[nid])
    return render_template('scanresult.html', items=items)


@app.route('/show_result/<string:nid>')
def show_result(nid):
    """ returns a page with results of URL Fuzzer """
    results = task_queue[nid].results
    return render_template('fuzzresult.html', results=results)


def generate_random_key():
    """ generates a unique random key """
    key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))
    if key in task_queue:
        key = generate_random_key()
    return key

def check_url(website):
    if not website.startswith('http'):
        website = 'http://' + website
    request = urllib2.Request(website)
    request.get_method = lambda : 'HEAD'
    try:
        response = urllib2.urlopen(request)
        return True
    except:
        return False

if __name__ == "__main__":
    app.run(debug=False)
