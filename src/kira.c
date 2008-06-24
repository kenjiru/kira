#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <err.h>

#include "sniff.h"
#include "util.h"

// variabile globale
int arphrd;
int mon_fd;
char* mon_ifname;
struct packet_info current_packet;

// variabile de configurare
char* ifname; // interfata wireless
int recv_buffer_size; // dim. bufferului
int sleep_time; // refresh-ul

int
main(int argc, char** argv)
{
	unsigned char buffer[8192];
	int len;
	
	// setez var. globale
	ifname = malloc(255*sizeof(char));
	strcpy(ifname, "wlan0");
	recv_buffer_size = 6750000;
	sleep_time = 1000;
	
	DEBUG("modul DEBUG activat\n");
	
	mon_fd = kira_open_packet_socket(ifname, sizeof(buffer), recv_buffer_size);
	if (mon_fd < 0)
		fprintf(stderr, "nu am putut deschide socketul\n");
	
	arphrd = kira_device_get_arptype();
	if (arphrd != ARPHRD_IEEE80211_PRISM &&
	    arphrd != ARPHRD_IEEE80211_RADIOTAP) {
		printf("Nu sunteti in modul monitor."
			   "Va rog sa folositi headerele radiotap sau prism2.\n");
		exit(1);
	}
	
	while ((len = kira_recv_packet(buffer, sizeof(buffer)))) {
		if (len == -1) {
			usleep(sleep_time);
			continue;
		}
		memset(&current_packet, 0, sizeof(current_packet));
		if (!kira_parse_packet(buffer, len)) {
			DEBUG("nu am putut parsa!\n");
			continue;
		}
	}
	
	return 0;
}
