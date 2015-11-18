'''
Created on Nov 13, 2015

@author: lite
'''

import socket
import sys
import threading
import time
from tcpsim.TCPSession import TCPSession


def connectTCP(ip, port):
    t = threading.Thread(target=connectTCP_fun, args=(ip, port))
    t.start()    
    

def connectTCP_fun(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    time.sleep(7)


if __name__ == '__main__':
    #connectTCP("10.204.70.34", 102)
    #argv: ipAddress, port, session count
    ip = sys.argv[1]
    port = int(sys.argv[2])
    iface = sys.argv[3]
    sessCnt = int(sys.argv[4])
    
    #connectTCP(ip, port)
    
    sessLst = []
    for i in range(sessCnt):
        sess = TCPSession(ip, port, iface)
        sess.start()
        sessLst.append(sess)
    
    for sess in sessLst:    
        sess.join()
    
    for sess in sessLst:
        sess.shutdown()        
        