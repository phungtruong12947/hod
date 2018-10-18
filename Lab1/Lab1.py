#!/usr/bin/env python3

import subprocess
import ipaddress
import sys
import time
import threading
import queue


class MultiplePing(object):

    def __init__(self, hosts):
        self.q = queue.Queue()
        self.r = queue.Queue()
        for host in hosts:
            self.q.put(host)

    def ping(self):
        while True:
            if not self.q.empty():
                host = self.q.get()
                args = ["ping", "-w", "1", host]
                p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = p.communicate()[0]
                output = bytes.decode(output)
                if "rtt" in output:
                    print(host + " is up")
                    self.r.put(host)
            else:
                break

    def ping_sweep(self):
        MAX_THREAD = 25
        running_thread = []
        for i in range(0, MAX_THREAD):
            t = threading.Thread(target=self.ping)
            t.start()
            running_thread.append(t)
        while True:
            for t in running_thread:
                if not t.isAlive():
                    running_thread.remove(t)
                    break
            if len(running_thread) == 0:
                break
        up_hosts = []
        while True:
            if not self.r.empty():
                host = self.r.get()
                up_hosts.append(host)
            else:
                break
        return up_hosts

class MultipleScan(object):
    def __init__(self, hosts):
        self.q = queue.Queue()
        self.r = queue.Queue()
        for host in hosts:
            self.q.put(host)

    def scan(self, host, mode):
        ports = []
        if mode == "tcp":
            print("Start TCP scan on " + host)
            args = "nc -z -v -w 1 " + host + " "
        elif mode == "udp":
            print("Start UDP scan on " + host)
            args = "nc -zv -u " + host + " "
        # scan first 100 common ports
        for i in range(1, 101):
            process = subprocess.Popen(
                args + str(i), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = bytes.decode(process.stderr.read())
            if "succeeded" in output:
                data = output.strip().split(' ')
                port_info = data[3] + " " + data[5] + " open"
                print(host + ":" + port_info)
                ports.append(port_info)
        return {host: ports}

    def merge(self, r1, r2):
        for k1, v1 in r1.items():
            for k2, v2 in r2.items():
                if k1 == k2:
                    v1 = v1 + v2
        return r1

    def do_scan(self):
        while True:
            if not self.q.empty():
                host = self.q.get()
                r1 = self.scan(host, "tcp")
                # r2 = scan(host, "udp")
                # r = self.merge(r1, r2)
                self.r.put(r1)
            else:
                break

    def run(self):
        MAX_THREAD = 3
        running_thread = []
        for i in range(0, MAX_THREAD):
            t = threading.Thread(target=self.do_scan)
            t.start()
            running_thread.append(t)
        while True:
            for t in running_thread:
                if not t.isAlive():
                    running_thread.remove(t)
                    break
            if len(running_thread) == 0:
                break
        total_r = []
        while True:
            if not self.r.empty():
                r = self.r.get()
                total_r.append(r)
            else:
                break
        return total_r


def cidr_to_hosts(cidr):
    net = ipaddress.ip_network(cidr)
    hosts = []
    for x in net:
        hosts.append(str(x))
    return hosts


if __name__ == '__main__':
    start_t = time.time()
    if '/' in sys.argv[1]:
        cidr = sys.argv[1]
        hosts = cidr_to_hosts(cidr)
    else:
        hosts = []
        hosts.append(sys.argv[1])
    mp = MultiplePing(hosts)
    up_hosts = mp.ping_sweep()
    if len(up_hosts) == 0:
        print("No hosts is up\nExit")
    else:
        mc = MultipleScan(up_hosts)
        total_r = mc.run()
        for x in total_r:
            for k, v in x.items():
                print("*****" + k + "*****")
                for val in v:
                    print(val+'\n')
    end_t = time.time()
    print("Runtime: " + str(end_t - start_t))
