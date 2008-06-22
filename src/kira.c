#include "kira.h"
#include "sniff.h"

int
main(int argc, char** argv)
{
	unsigned char buffer[8192];
	int len;
	double freq;
	
	DEBUG("Modul debug activat!");
	
	mon_fd = kira_open_packet_socket(ifname, sizeof(buffer), recv_buffer_size);
	if (mon_fd < 0)
		err(1, "Couldn't open packet socket");
	
	return 0;
}
