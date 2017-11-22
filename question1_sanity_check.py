import sys
import re
from scapy.all import *

# TCP Flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# ANSI Color
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

str_OK = bcolors.OKGREEN + 'OK' + bcolors.ENDC
str_ERROR = bcolors.FAIL + 'ERROR' + bcolors.ENDC

def main(pcap_file):
    num_rst = 0
    has_404 = False

    packets = rdpcap(pcap_file)
    for packet in packets:
        if not TCP in packet: 
            continue
        if packet[TCP].flags & RST:
            num_rst += 1
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            payload = str(packet[TCP].payload)
            if re.match('\w+', payload):
                if re.match('.*404 Not Found.*', payload):
                    has_404 = True

    print '%d packets avaliable in %s' % (len(packets), pcap_file)
    print '[%s] %d TCP reset packets in pcap' % (str_OK if num_rst >= 2 else str_ERROR, num_rst)
    print '[%s] HTTP 404 Status %s' % ((str_OK, 'Found') if has_404 else (str_ERROR, 'Missing'))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print 'usage: python question1_sanity_check.py [pcap_file]'
    else:
        main(sys.argv[1])
        