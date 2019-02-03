This is a very basic TCP traffic simulator. The code is pretty much self-explanatory.

Call it as:
python3 -m tcpsim.TCPSim "10.204.70.34" 102 eth0 1

You may need to block incoming RST packets before you the script:
sudo iptables -A OUTPUT -d 10.204.70.34 -p tcp --tcp-flags RST RST -j DROP
