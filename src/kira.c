#include "kira.h"
#include "sniff.h"

int
main(int argc, char** argv)
{
	unsigned char buffer[8192];
	
	// setez var. globale
	ifname = malloc(255*sizeof(char));
	strcpy(ifname, "wlan0");
	recv_buffer_size = 6750000;
	sleep_time = 1000;
	
	DEBUG("Modul debug activat!\n");
	
	mon_fd = kira_open_packet_socket(ifname, sizeof(buffer), recv_buffer_size);
	if (mon_fd < 0)
		fprintf(stderr, "nu am putut deschide socketul\n");
	
	return 0;
}
