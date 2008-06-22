#include "kira.h"
#include "sniff.h"

extern int mon_fd;
extern char* mon_ifname;

int
kira_open_packet_socket(char* 	devname, 
						size_t 	bufsize, 
						int 	recv_buffer_size)
{
	int ret;
	int ifindex;

	mon_ifname = devname;

	mon_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (mon_fd < 0)
		err(1, "nu am putut crea socketul");

	return mon_fd;
}
