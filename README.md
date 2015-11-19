
python3 -m tcpsim.TCPSim "10.204.70.34" 102 eth0 1

 sudo iptables -A OUTPUT -d 10.204.70.34 -p tcp --tcp-flags RST RST -j DROP