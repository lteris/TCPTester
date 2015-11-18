'''
Created on Nov 16, 2015

@author: lite
'''

import socket
from threading import Thread
#import scapy.all as scapy
from scapy.all import IP,TCP
import struct
import random
import time
import functools
import ctypes
import fcntl

flagDict = {"F":0x1, "S":0x2, "R":0x4, "P":0x8, 
            "A":0x10, "U":0x20, "E":0x40, "C":0x80}

class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

def setSockPromisc(sock, iface):
    IFF_PROMISC = 0x100
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    
    ifr = ifreq()
    ifr.ifr_ifrn = byte(iface)
    
    fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)
    ifr.ifr_flags |= IFF_PROMISC    
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)
    
def unsetSockPromisc(sock, iface):
    IFF_PROMISC = 0x100
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    
    ifr = ifreq()
    ifr.ifr_ifrn = byte(iface)
    
    fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)
    ifr.ifr_flags &= ~IFF_PROMISC
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)


def getLocalIp(iface = 'eth0'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockfd = sock.fileno()
    SIOCGIFADDR = 0x8915

    ifreq = struct.pack('16sH14s', bytes(iface, 'utf-8'), 
                        socket.AF_INET, bytes('\x00'*14, 'utf-8'))
    try:
        res = fcntl.ioctl(sockfd, SIOCGIFADDR, ifreq)
    except:
        return None
    ip = struct.unpack('16sH2x4s8x', res)[2]
    ip = socket.inet_ntoa(ip)
    sock.close()
    return ip
  


def getSrcIp(bstr):
    return "".join(str(int(i)) + '.' for i in bstr[12:16])[:-1]

def getDstIp(bstr):
    return "".join(str(int(i)) + '.' for i in bstr[16:20])[:-1]

def getSrcPort(bstr):
    iphl = (bstr[0] & 0xf) * 4
    return struct.unpack(">H", bstr[iphl:iphl+2])[0]

def getDstPort(bstr):
    iphl = (bstr[0] & 0xf) * 4
    return struct.unpack(">H", bstr[iphl+2:iphl+4])[0]

def pktIsTCP(bstr):
    return bstr[9] == 0x06

def printPkt(bstr):
    print(getSrcIp(bstr)+"|" + getDstIp(bstr) + "|" 
          + str(getSrcPort(bstr)) +"|" + str(getDstPort(bstr)))
    print([hex(i) for i in bstr])

'''
    flags C E U A P R S F
'''    
def genIpPacket(srcIp, dstIp, sport, dport, seqNo, ackNo, flags):
    
    flgNo = functools.reduce(lambda x, y: x | flagDict[y], flags, 0)
    
    ip=(IP(src=srcIp, dst=dstIp, )/
        TCP(sport=sport, dport=dport, seq=seqNo, ack=ackNo, flags=flgNo))
    
    bs = ip.build()    
    return bs

def disIpPacket(bstr):
    ip = IP()/TCP()
    ip.dissect(bstr)
    return ip    
  
class TCPSession(Thread):
    
    def __init__(self, serverIp="10.204.70.34", serverPort=102, iface="eth0"):
        Thread.__init__(self)
        
        self.fsm = {"STATE_SYN" : {"act" : self.doSynHS, "goto" : "STATE_KA"},
               "STATE_KA" : {"act" : self.doKA, "goto" : "STATE_FIN"},
               "STATE_FIN" : {"act" : self.doFin, "goto" : "STATE_DONE"}}
        
        random.seed()
        
        self._localIp = getLocalIp(iface)
        self._serverIp = serverIp
        self._serverPort = serverPort
        self._iface = iface
        
        #get a port and bind to it
        try:
            
            # create a raw socket and bind it to the public interface
            self._sockout = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.SOCK_RAW)
            self._sockout.setsockopt(socket.IPPROTO_IP, socket.SO_REUSEADDR, 1)
            HOST = socket.gethostbyname(socket.gethostname())
            
            self._sockout.bind((self._localIp, 0))
            self._localPort = random.randint(10000,60000)
            self._sockout.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                                   
            
            
            self._sockin = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)            
        except socket.error as e:
            print(">>>>> Error building socket" + str(e))
            
        self._state = "STATE_SYN"

    def shutdown(self):
        try:
            self._sockin.close()
            self._sockout.close()
        except socket.error as e:
            print(e)
        
    def run(self):
        while self._state != "STATE_DONE":
            fct = self.fsm[self._state]["act"]
            fct()
            #self._state = fsm[self._state]["goto"]
            break #remove
            
        (bstr, _) = self._sockin.recvfrom(65565)
        if self.inPktMatches(bstr):
            ip = disIpPacket(bstr)
            ip.show()
            printPkt(bstr)
            
                
    def tstSelf(self):
        bpkt = genIpPacket(self._localIp, self._serverIp, 
                           self._localPort, self._serverPort,
                           100, 99, 0x10)
        printPkt(bpkt)
        print('----------------------------------------')
        disIpPacket(bpkt).show()
    
    def inPktMatches(self, bstr):
        return (pktIsTCP(bstr) and 
                getSrcIp(bstr) == self._serverIp and
                getDstIp(bstr) == self._localIp and  
                getSrcPort(bstr) == self._serverPort and 
                getDstPort(bstr) == self._localPort)
        
    ''' initiate and complete syn hs '''    
    def doSynHS(self):
        seqNo = random.randint(1000,60000)
        bpkt = genIpPacket(self._localIp, self._serverIp, 
                           self._localPort, self._serverPort, seqNo, 0, "S")
        
        self._sockout.sendto(bpkt, (self._serverIp, 0))
        
        self._state = "STATE_KA"
    
    def doKA(self):
        print(">>>>>>>>>>> doKA")                
    
    def doFin(self):
        print(">>>>>>>>>>> doFIN")
        while 1:
            pass
    
class BrokenTCP(TCPSession):
    
    def onAck(self):
        #do nothing - trigger a fin from the server???
        pass
    
    def onFin(self):
        #default - reply with ack only - let the server hang in finwait2?
        pass