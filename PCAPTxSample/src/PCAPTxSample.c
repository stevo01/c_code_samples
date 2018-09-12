/*
 ============================================================================
 Name        : RawSocketSample.c
 Author      : Steffen Volkmann
 Version     :
 Copyright   : 
 Description : This application demonstrates the usage of raw socket
 network interface.

 bookmarks:
 http://plasmixs.github.io/raw-sockets-programming-in-c.html

/*system includes*/
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <pcap.h>

#define MAX_PACK_SIZE 9000
#define ETHER_TYPE_HCI_TP 0xF000

static char TxBuff[MAX_PACK_SIZE];
static char pcap_errbuf[PCAP_ERRBUF_SIZE];

static pcap_t* rawsocket_open(char *ifName, u_int8_t *pDst) {
	printf("open socket interface %s", ifName);

	int txsockfd = -1;
	struct ifreq if_mac;
	pcap_t* pcap;


	// open socket interface
	if ((txsockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		return -1;
	}

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
	if (ioctl(txsockfd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		return -1;
	}

	/* set ethernet header data */
	struct ether_header *eth_header = (struct ether_header *) &TxBuff;
	/* Ethernet header */
	eth_header->ether_shost[0] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[0];
	eth_header->ether_shost[1] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[1];
	eth_header->ether_shost[2] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[2];
	eth_header->ether_shost[3] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[3];
	eth_header->ether_shost[4] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[4];
	eth_header->ether_shost[5] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[5];
	memcpy(eth_header->ether_dhost, pDst, 6);
	eth_header->ether_type = htons(ETHER_TYPE_HCI_TP); /* Ethertype field  e.g. ETH_P_IP */

	close(txsockfd);

    pcap_errbuf[0]='\0';
    pcap=pcap_open_live(ifName,96,0,0,pcap_errbuf);

    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!pcap) {
        return NULL;
    }

    return pcap;

}

static int rawsocket_send(pcap_t* pcap, u_int8_t* data, u_int32_t len) {

	if (len > MAX_PACK_SIZE) {
		printf("error len=%d", len);
	}

	memcpy(&TxBuff[sizeof(struct ether_header)], data, len);
	len += sizeof(struct ether_header);

	/* Send packet */

    // Write the Ethernet frame to the interface.
    if (pcap_inject(pcap,&TxBuff,len)==-1) {
        pcap_perror(pcap,0);
        pcap_close(pcap);
        return -1;
    }

	printf("send package with %d bytes\n", len);

	return len;
}

int main(int argc, char *argv[]) {

	pcap_t* pcap;
	char *ifname;
	int idx;


	u_int8_t Dst[6] = { 0x90, 0x1b, 0x0e, 0xa4, 0x01, 0x5e };
	u_int8_t sample_data[255];

	for (idx = 0; idx < 255; idx++) {
		sample_data[idx] = idx;
	}

	if (argc == 2) {
		ifname = argv[1];
		printf("send raw data via socket interface %s\n", ifname);
	} else if (argc > 2) {
		printf("Too many arguments supplied.\n");
		return -1;
	} else {
		printf(
				"use command line argument to specify the name of network interface\n");
		printf(
				"e.g. start application with following command \"RawSocketTxSample eth0\"\n");
		return -1;
	}

	/*open interface*/
	pcap = rawsocket_open(argv[1], Dst);

	if (pcap != NULL) {
		printf("opening the socket %s was successful\n", ifname);
		for (idx = 1; idx < 200; idx++) {
			rawsocket_send(pcap, sample_data, idx);
		}
	} else {
		printf("opening the socket %s was faulty\n", ifname);
	}

	return EXIT_SUCCESS;
}





#if 0
 ============================================================================
 */
// This is an example program from the website www.microhowto.info
// © 2012 Graham Shaw
// Copying and distribution of this software, with or without modification,
// is permitted in any medium without royalty.
// This software is offered as-is, without any warranty.

// Purpose: to construct an ARP request and write it to an Ethernet interface
// using libpcap.
//
// See: "Send an arbitrary Ethernet frame using libpcap"
// http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap.html

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

int main(int argc,const char* argv[]) {
    // Get interface name and target IP address from command line.
    if (argc<2) {
        fprintf(stderr,"usage: send_arp <interface> <ipv4-address>\n");
        exit(1);
    }
    const char* if_name=argv[1];
    const char* target_ip_string=argv[2];

    // Construct Ethernet header (except for source MAC address).
    // (Destination set to broadcast address, FF:FF:FF:FF:FF:FF.)
    struct ether_header header;
    header.ether_type=htons(ETH_P_ARP);
    memset(header.ether_dhost,0xff,sizeof(header.ether_dhost));

    // Construct ARP request (except for MAC and IP addresses).
    struct ether_arp req;
    req.arp_hrd=htons(ARPHRD_ETHER);
    req.arp_pro=htons(ETH_P_IP);
    req.arp_hln=ETHER_ADDR_LEN;
    req.arp_pln=sizeof(in_addr_t);
    req.arp_op=htons(ARPOP_REQUEST);
    memset(&req.arp_tha,0,sizeof(req.arp_tha));

    // Convert target IP address from string, copy into ARP request.
    struct in_addr target_ip_addr={0};
    if (!inet_aton(target_ip_string,&target_ip_addr)) {
       fprintf(stderr,"%s is not a valid IP address",target_ip_string);
       exit(1);
    }
    memcpy(&req.arp_tpa,&target_ip_addr.s_addr,sizeof(req.arp_tpa));

    // Write the interface name to an ifreq structure,
    // for obtaining the source MAC and IP addresses.
    struct ifreq ifr;
    size_t if_name_len=strlen(if_name);
    if (if_name_len<sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
        fprintf(stderr,"interface name is too long");
        exit(1);
    }

    // Open an IPv4-family socket for use when calling ioctl.
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1) {
        perror(0);
        exit(1);
    }

    // Obtain the source IP address, copy into ARP request
    if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }
    struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&req.arp_spa,&source_ip_addr->sin_addr.s_addr,sizeof(req.arp_spa));

    // Obtain the source MAC address, copy into Ethernet header and ARP request.
    if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }
    if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
        fprintf(stderr,"not an Ethernet interface");
        close(fd);
        exit(1);
    }
    const unsigned char* source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;
    memcpy(header.ether_shost,source_mac_addr,sizeof(header.ether_shost));
    memcpy(&req.arp_sha,source_mac_addr,sizeof(req.arp_sha));
    close(fd);

    // Combine the Ethernet header and ARP request into a contiguous block.
    unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(frame,&header,sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp));

    // Open a PCAP packet capture descriptor for the specified interface.
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    pcap_t* pcap=pcap_open_live(if_name,96,0,0,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    // Write the Ethernet frame to the interface.
    if (pcap_inject(pcap,frame,sizeof(frame))==-1) {
        pcap_perror(pcap,0);
        pcap_close(pcap);
        exit(1);
    }

    // Close the PCAP descriptor.
    pcap_close(pcap);
    return 0;
}
#endif
