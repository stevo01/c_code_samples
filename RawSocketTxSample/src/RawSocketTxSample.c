/*
 ============================================================================
 Name        : RawSocketSample.c
 Author      : Steffen Volkmann
 Version     :
 Copyright   : 
 Description : This application demonstrates the usage of raw socket
 network interface.
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
static struct sockaddr_ll socket_address;

static int rawsocket_open(char *ifName, u_int8_t *pDst) {
	printf("open socket interface");

	int txsockfd = -1;
	struct ifreq if_idx;
	struct ifreq if_mac;

	// open socket interface
	if ((txsockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		return -1;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, (IFNAMSIZ - 1));
	if (ioctl(txsockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
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
	eth_header->ether_type = htons(ETHER_TYPE_HCI_TP /*ETH_P_IP*/); /* Ethertype field */

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	memcpy(socket_address.sll_addr, pDst, 6);

	return txsockfd;
}

static void rawsocket_send(int txsockfd, u_int8_t* data, u_int32_t len) {

	if (len > MAX_PACK_SIZE) {
		printf("error len=%d", len);
	}

	memcpy(&TxBuff[sizeof(struct ether_header)], data, len);
	len += sizeof(struct ether_header);

	/* Send packet */
	if (sendto(txsockfd, TxBuff, len, 0, (struct sockaddr*) &socket_address,
			sizeof(struct sockaddr_ll)) < 0) {
		printf("sendto failed len=%d\n", len);
		perror("Send failed");
	}

	return;
}

int main(int argc, char *argv[]) {

	int txsockfd;
	char *ifname;
	int idx;
	u_int8_t Dst[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	u_int8_t sample_data[5] = { 0x01, 0x01, 0x23, 0x23, 0x23 };

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
		for (idx = 0; idx < 100; idx++) {
			rawsocket_send(txsockfd, sample_data, sizeof(sample_data));
		}
	} else {
		printf("opening the socket %s was faulty\n", ifname);
	}

	return EXIT_SUCCESS;
}
