#include <netinet/ether.h>
#include <net/ethernet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>


#include "getmac.h"

char* getMacAddr (char *argv)
{

	struct ifreq *iflist;
	struct sockaddr *sa;
	int fd;
	static char *out;


	iflist = (struct ifreq *)malloc (sizeof (struct ifreq));

	fd = socket (PF_INET, SOCK_STREAM, 0);

	strncpy (iflist->ifr_name, argv, strlen (argv));
	
    //try {
	if (ioctl (fd, SIOCGIFHWADDR, iflist) == -1)
        {
            perror ("ioctl failed");
            //throw "error";
        }
    //} catch (int i){

    //}

	sa = &(iflist->ifr_hwaddr);

	//printf("getmac in integer : %02x:%02x:%02x:%02x:%02x:%02x\n", 
	//	sa->sa_data[0], sa->sa_data[1], sa->sa_data[2], 
	//	sa->sa_data[3], sa->sa_data[4], sa->sa_data[5]);
    	//printf("sa->sa_data : %s\n", sa->sa_data);
		

	out = ether_ntoa ((struct ether_addr *) sa->sa_data);
    //printf("in getmac.cpp : %s\n", out);
	//printf ("%s\n", out);

	return out;
}
