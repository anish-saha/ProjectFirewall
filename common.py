#!/usr/bin/env python

import time
import threading
from scapy.all import *
import sys
import socket
import json
import Queue
import interfaces

maxhop = 25

# A request that will trigger the great firewall but will NOT cause
# the web server to process the connection.  You probably want it here

triggerfetch = """GET /search?q=project+three HTTP/1.1\nhost: www.google.com"""

# A couple useful functions that take scapy packets
def isRST(p):
    return (TCP in p) and (p[IP][TCP].flags & 0x4 != 0)

def isICMP(p):
    return ICMP in p

def isTimeExceeded(p):
    return ICMP in p and p[IP][ICMP].type == 11

# A general python object to handle a lot of this stuff...
#
# Use this to implement the actual functions you need.
class PacketUtils:
    def __init__(self, dst=None):
        # Get one's SRC IP & interface
        i = interfaces.interfaces()
        self.src = i[1][0]
        self.iface = i[0]
        self.netmask = i[1][1]
        self.enet = i[2]
        self.dst = dst
        sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" %
                         (self.src, self.iface, self.netmask, self.enet))
        # A queue where received packets go.  If it is full
        # packets are dropped.
        self.packetQueue = Queue.Queue(100000)
        self.dropCount = 0
        self.idcount = 0

        self.ethrdst = ""

        # Get the destination ethernet address with an ARP
        self.arp()
        
        # You can add other stuff in here to, e.g. keep track of
        # outstanding ports, etc.
        
        # Start the packet sniffer
        t = threading.Thread(target=self.run_sniffer)
        t.daemon = True
        t.start()
        time.sleep(.1)

    # generates an ARP request
    def arp(self):
        e = Ether(dst="ff:ff:ff:ff:ff:ff",
                  type=0x0806)
        gateway = ""
        srcs = self.src.split('.')
        netmask = self.netmask.split('.')
        for x in range(4):
            nm = int(netmask[x])
            addr = int(srcs[x])
            if x == 3:
                gateway += "%i" % ((addr & nm) + 1)
            else:
                gateway += ("%i" % (addr & nm)) + "."
        sys.stderr.write("Gateway %s\n" % gateway)
        a = ARP(hwsrc=self.enet,
                pdst=gateway)
        p = srp1([e/a], iface=self.iface, verbose=0)
        self.etherdst = p[Ether].src
        sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))


    # A function to send an individual packet.
    def send_pkt(self, payload=None, ttl=32, flags="",
                 seq=None, ack=None,
                 sport=None, dport=80,ipid=None,
                 dip=None,debug=False):
        if sport == None:
            sport = random.randint(1024, 32000)
        if seq == None:
            seq = random.randint(1, 31313131)
        if ack == None:
            ack = random.randint(1, 31313131)
        if ipid == None:
            ipid = self.idcount
            self.idcount += 1
        t = TCP(sport=sport, dport=dport,
                flags=flags, seq=seq, ack=ack)
        ip = IP(src=self.src,
                dst=self.dst,
                id=ipid,
                ttl=ttl)
        p = ip/t
        if payload:
            p = ip/t/payload
        else:
            pass
        e = Ether(dst=self.etherdst,
                  type=0x0800)
        # Have to send as Ethernet to avoid interface issues
        sendp([e/p], verbose=1, iface=self.iface)
        # Limit to 20 PPS.
        time.sleep(.05)
        # And return the packet for reference
        return p


    # Has an automatic 5 second timeout.
    def get_pkt(self, timeout=5):
        try:
            return self.packetQueue.get(True, timeout)
        except Queue.Empty:
            return None

    # The function that actually does the sniffing
    def sniffer(self, packet):
        try:
            # non-blocking: if it fails, it fails
            self.packetQueue.put(packet, False)
        except Queue.Full:
            if self.dropCount % 1000 == 0:
                sys.stderr.write("*")
                sys.stderr.flush()
            self.dropCount += 1

    def run_sniffer(self):
        sys.stderr.write("Sniffer started\n")
        rule = "src net %s or icmp" % self.dst
        sys.stderr.write("Sniffer rule \"%s\"\n" % rule);
        sniff(prn=self.sniffer,
              filter=rule,
              iface=self.iface,
              store=0)

    # Sends the message to the target in such a way
    # that the target receives the msg without
    # interference by the Great Firewall.
    #
    # ttl is a ttl which triggers the Great Firewall but is before the
    # server itself (from a previous traceroute incantation
    def evade(self, target, msg, ttl):
        result = ""
        # Send the initial SYN packet
        self.send_pkt(flags="S", sport=source_port, dip=target)
        response = self.get_pkt()
        if response == None:
            return "DEAD"
        # Get the ACK and SEQ values from the server-end response
        ack = response[TCP].ack
        seq = response[TCP].seq

        for i in range(len(msg)-1):
            self.send_pkt(payload=msg[i:i+1], flags="A", seq=ack+i, ack=seq+i+1, sport=sport, dip=target)
            self.send_pkt(payload='x', ttl=ttl, flags="A", seq=ack+i, ack=seq+i+1, sport=sport, dip=target)
        while (self.packetQueue.qsize() > 0):
            response = self.get_pkt()
            if response == None:
                return "ERROR"
            if isRST(response):
                return "RST"
            if not isTimeExceeded(response) and 'Raw' in response:
                result += str(packet['Raw'].load)
        # Return the reconstructed packet after appending all parts of the msg
        return result

        
    # Returns "DEAD" if server isn't alive,
    # "LIVE" if the server is alive,
    # "FIREWALL" if it is behind the Great Firewall
    def ping(self, target):
        # self.send_msg([triggerfetch], dst=target, syn=True)
        source_port = random.randint(2000, 30000)
        payload = "GET /search?q=Falun+Gong HTTP/1.1\nhost: www.google.com\n\n"
        # Send the initial SYN packet to initialize the 3-way handshake
        self.send_pkt(flags="S", sport=source_port, dip=target)
        response = self.get_pkt()
        if response == None:
            return "DEAD"
        # Get the ACK and SEQ values from the server-end response
        ack = response[TCP].ack
        seq = response[TCP].seq
        # Complete the 3-way handshake and send the payload
        self.send_pkt(flags="A", seq=ack, ack=seq+1, sport=source_port, dip=target)
        self.send_pkt(payload=payload, flags="PA", seq=ack, ack=seq+1, sport=source_port, dip=target)
        # Ensure that there are no more packets to be sent
        while (self.packetQueue.qsize() > 0):
            response = self.get_pkt()
            if response == None:
                return "LIVE"
            if isRST(response):
                return "FIREWALL"
        response = self.get_pkt()
        # Finally check the whether the server responded with an RST packet
        if response == None:
            return "LIVE"
        if isRST(response):
            return "FIREWALL"
        return "LIVE"

    # Format is
    # ([], [])
    # The first list is the list of IPs that have a hop
    # or none if none
    # The second list is T/F 
    # if there is a RST back for that particular request
    def traceroute(self, target, hops):
        ipList = [None for _ in xrange(hops)] 
        rstList = [False for _ in xrange(hops)]
        prev_ips = [None for _ in xrange(hops)]
        # Initialization of variables
        source_port = random.randint(2000, 30000)
        payload = "GET /search?q=Falun+Gong HTTP/1.1\nhost: www.google.com\n\n"
        num_copies = 3
        # Send the initial SYN packet
        self.send_pkt(flags="S", sport=source_port, dip=target)
        response = self.get_pkt()
        if response == None:
            return "DEAD"
        # Get the ACK and SEQ values from the server-end response
        ack = response[TCP].ack
        seq = response[TCP].seq
        # Complete the 3-way handshake
        self.send_pkt(flags="A", seq=ack, ack=seq+1, sport=source_port, dip=target)
        # Send num_copies payload copies to the target server for each hop
        for i in range(hops):
            for j in range(num_copies):
                self.send_pkt(payload=payload, ttl=i, flags="PA", seq=ack, ack=seq+1, sport=source_port, dip=target)
                while (self.packetQueue.qsize() > 0):
                    response = self.get_pkt()
                    if response == None:
                        return "ERROR"
                    curr = response[IP].src
                    if isRST(response):
                        rstList[i] = True
                    if isTimeExceeded(response) and curr not in prev_ips:
                        ipList[i] = curr
                        prev_ips[i] = curr
                    else:
                        continue
        # Return the list of IPs that have a ahop and the list of whether each response is a IMCP/RST.
        return (ipList, rstList)

