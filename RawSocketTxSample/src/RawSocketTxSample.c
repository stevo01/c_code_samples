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

============================================================================
*/

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
#include <pthread.h>

#define MAX_PACK_SIZE 9000
#define ETHER_TYPE_HCI_TP 0xF000

static char TxBuff[MAX_PACK_SIZE];

static int rawsocket_open(char *ifName, u_int8_t *pDst) {
	printf("open socket interface %s", ifName);

	int txsockfd = -1;
	struct ifreq if_mac;
	static struct sockaddr_ll socket_address;

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


	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sll_family = PF_PACKET;
	socket_address.sll_ifindex = if_nametoindex(ifName);
	socket_address.sll_protocol = htons(ETH_P_ALL);


	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];



	if (bind(txsockfd, (struct sockaddr*) &socket_address,
			sizeof(socket_address)) < 0) {
		perror("Bind");
		return -1;
	}

	return txsockfd;
}

static void rawsocket_send(int txsockfd, u_int8_t* data, u_int32_t len) {

	if (len > MAX_PACK_SIZE) {
		printf("error len=%d", len);
	}

	memcpy(&TxBuff[sizeof(struct ether_header)], data, len);
	len += sizeof(struct ether_header);

	/* Send packet */
	if (send(txsockfd, TxBuff, len, 0) < 0) {
		printf("sendto failed len=%d\n", len);
		perror("Send failed");
	}

	printf("send package with %d bytes\n", len);

	return;
}

int main(int argc, char *argv[]) {

	int txsockfd;
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
	txsockfd = rawsocket_open(argv[1], Dst);

	if (txsockfd != -1) {
		printf("opening the socket %s was successful\n", ifname);
		for (idx = 1; idx < 200; idx++) {
			rawsocket_send(txsockfd, sample_data, idx);
		}
	} else {
		printf("opening the socket %s was faulty\n", ifname);
	}

	return EXIT_SUCCESS;
}
