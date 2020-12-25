# arp-spoofing
<strong>_arp-spoofing_</strong> computers around you that shares same network with yours using _pcap_ C network library. 
<br/><strong style="color:red">Be aware not to attack others in a public network!!</strong>

## Usage
syntax: `send-arp-test <interface> <senderIP> <targetIP>`

sample: `send-arp-test wlan0 172.30.1.40 172.30.1.254`

- `<interface>` : name of network that you use
- `<senderIP>` : packet sender in a arp-spoofing system
- `<targetIP>` : packet receiver in a arp-spoofing system
