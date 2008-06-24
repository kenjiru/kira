#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/wireless.h>

#include "sniff.h"
#include "util.h"

extern int mon_fd;
extern char* mon_ifname;

int
kira_open_packet_socket(char* devname, 
		size_t 	bufsize,
		int 	recv_buffer_size)
{
	int ret;
	int ifindex;

	mon_ifname = devname;

	mon_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (mon_fd < 0)
		fprintf(stderr, "nu am putut crea socketul\n");
	
	// determina id-ul interfetei wireless
	ifindex = kira_device_index(mon_fd, devname);
	
	struct sockaddr_ll sall;
	sall.sll_ifindex = ifindex;
	sall.sll_family = AF_PACKET;
	sall.sll_protocol = htons(ETH_P_ALL);
	
	ret = bind(mon_fd, (struct sockaddr*)&sall, sizeof(sall));
	if (ret != 0)
		fprintf(stderr, "bind a esuat\n");
	
	kira_device_promisc(mon_fd, devname, 1);
	kira_set_receive_buffer(mon_fd, recv_buffer_size);

	return mon_fd;
}

int
kira_device_index(int fd, 
		const char *devname)
{
	struct ifreq req;

	strncpy(req.ifr_name, devname, IFNAMSIZ);
	req.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFINDEX, &req) < 0)
		fprintf(stderr, "nu am gasit interfata %s\n", devname);

	if (req.ifr_ifindex < 0) {
		fprintf(stderr, "interface %s not found\n", devname);
	}
	DEBUG("index %d\n", req.ifr_ifindex);
	return req.ifr_ifindex;
}

void
kira_device_promisc(int fd, 
		const char *devname, 
		int on)
{
	struct ifreq req;

	strncpy(req.ifr_name, devname, IFNAMSIZ);
	req.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFFLAGS, &req) < 0) {
		fprintf(stderr, "nu am putut seta interfata %s\n", devname);
	}

	req.ifr_flags |= IFF_UP;

	if (on)
		req.ifr_flags |= IFF_PROMISC;
	else
		req.ifr_flags &= ~IFF_PROMISC;

	if (ioctl(fd, SIOCSIFFLAGS, &req) < 0) {
		fprintf(stderr, "nu am putut seta modul promisc pentru interfata %s\n", devname);
	}
}

void
kira_set_receive_buffer(int fd, 
		int sockbufsize)
{
	int ret;

	/* valoarea maxima permisa, setat de rmem_max sysctl */
	FILE* PF = fopen("/proc/sys/net/core/rmem_max", "w");
	fprintf(PF, "%d", sockbufsize);
	fclose(PF);

	ret = setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &sockbufsize, sizeof(sockbufsize));
	if (ret != 0)
		fprintf(stderr, "nu am putut seta optiunile pentru socket\n");
}

int
kira_device_get_arptype(void)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, mon_ifname, sizeof(ifr.ifr_name));

	if (ioctl(mon_fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "nu am putut determina tipul ARP\n");
	}
	DEBUG("ARPTYPE %d\n", ifr.ifr_hwaddr.sa_family);
	return ifr.ifr_hwaddr.sa_family;
}

inline int
kira_recv_packet(unsigned char* buffer, 
		size_t bufsize)
{
	return recv(mon_fd, buffer, bufsize, MSG_DONTWAIT);
}


