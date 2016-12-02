import socket
import sys
import pprint
import requests
import json
import urllib2
import codecs
import nmap
from slacker import Slacker
from struct import *

#You must install nmap and slacker!

#Dictionary to hold list of previously seen mac addresses
macDict = {}

#Determine if we have seen this mac address before
def isNew(mac):
    if mac in macDict:
        return 0
    else:
        return 1

#Adds a new mac to the dictionary
def addMac(mac):
    macDict[mac] = 1

#Gets the vendor of the NIC based on the OUI of the mac address
def getVendor(mac):
    MAC_URL = 'http://macvendors.co/api/' + mac
    request = urllib2.Request(MAC_URL, headers={'User-Agent' : "API Browser"})
    response = urllib2.urlopen(request)
    reader = codecs.getreader("utf-8")

    try:
        obj = json.load(reader(response))
        return obj['result']['company']
    except KeyError:
        return "Could not get Vendor"
    except ValueError:
        return "Could not get Vendor"

#Parse the IP header
def parseIp(packet):
    eth_length=14
    ip_header = packet[eth_length:20+eth_length]
    iph = unpack('!BBHHHBBH4s4s', ip_header)

#Post to Slack
    #You Must fill in a channel and API Key!
def postSlack(msg):
    slack = Slacker('<Your-API-Key-Here>')
    slack.chat.post_message('channelName', msg)

#Parse MAC Address
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b



#---Main---

try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(65565)

    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    ip_header = packet[eth_length:20+eth_length]
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    dest_mac = eth_addr(packet[0:6])
    src_mac = eth_addr(packet[6:12])

    dest_ip = socket.inet_ntoa(iph[9])
    src_ip = socket.inet_ntoa(iph[8])

    if isNew(src_mac):
        addMac(src_mac)
        if src_ip.startswith('192.168.'):
            msg = '\nNew MAC Found: ' + src_mac + '\n'
            msg += getVendor(src_mac)
            msg += '\n'
            nm = nmap.PortScanner()
            nm.scan(hosts=src_ip, arguments='-O -sS')
            for host in nm.all_hosts():
                msg += '-------------------------------------\n'
                msg +='Host : %s (%s)' % (host, nm[host].hostname()) + '\n'
                msg += 'State : %s' % nm[host].state() + '\n'

                for proto in nm[host].all_protocols():
                    msg += '----------\n'
                    msg += 'Protocol : %s' % proto + '\n'

                    lport = nm[host][proto].keys()
                    lport.sort()
                    for port in lport:
                        msg +='port : %s\tstate : %s' % (port, nm[host][proto][port]['state']) + '\n'
            postSlack(msg)
            #print(msg)


