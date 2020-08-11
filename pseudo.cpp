//pseudo-code for arp-spoofing

class ARP_packet {

	char* ethersrc;
	char* etherdest;
	char* arpop;

	...

}

 sendPacket()

char* getSenderMac(){
	
	return senderMac;
}

void receivePacket(){ // not good .. it's better not to extract code as func.
	
	if(ehdr->ether_type == 0x0800){
		ihdr = (struct ihdr *)packet0;
	} else if(ehdr->ether_type == 0x86DD){
		ihdr6 = (struct ihdr6 *)packet0;
	} else if(ehdr->ether_type == 0x0806){
		ahdr6 = (struct ahdr6 *)packet0;
	} 

	sprintf();
}



int main(int argc, char* argv[]){
	
	// Stage1
	ARP_packet arp1 = new ARP_packet(ethersrc, etherdest, arpop, ..);
	send_packet(arp1, .. );

	// Stage2
	receivePakcet();	// while(1) .. // get sender's Mac

	// Stage3
	ARP_packet arp_attack1 = new ARP_packet(ethersrc, etherdest, arpop, ..);
	send_packet(arp_attack1, .. );
	
	// Stage4
	char* result = receivePacket(); 
	// while(1) ... // get spoofed IP packet

	IP_packet ip1 = new IP_packet(result, ... ); 

	// Stage5
	send_packet(ip1, ... );

	// Stage6
	receivePacket(); // while(1) .. 
	// get ARP request packet
	// get ARP broadcast packet 	
	// packet in order to update its arp-table 

	// Stage7
	ARP_packet arp_unicast = new ARP_packet(ethersrc, etherdest, ..);
	send_packet(arp_unicast, ... );

	// Stage8
	ARP_packet arp_attack2 = new ARP_packet(ethersrc, etherdest, ..);
	send_packet(arp_attack2, ... );

}

// wireshark filter command
// arp || eth.addr == 00:0c:29:f2:41:76 || eth.addr == a0:c5:89:77:cb:03 


















