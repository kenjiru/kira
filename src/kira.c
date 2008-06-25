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
#include "parse.h"
#include "util.h"

// variabile globale
int arphrd;
struct packet_info current_packet;
short current_channel;

int
main(int argc, char** argv)
{
	int fd;
	char* devname = "wlan0";
	int sleep_time = 1000;
	int recv_buffer_size = 6750000;
	unsigned char buffer[8192];
	int len;
	double freq;
	
	DEBUG("modul DEBUG activat\n");
	
	fd = kira_open_packet_socket(devname, sizeof(buffer), recv_buffer_size);
	if (fd < 0)
		err(1, "Nu am putut deschide socketul\n");
	
	arphrd = kira_device_get_arptype(fd, devname);
	if (arphrd != ARPHRD_IEEE80211_PRISM &&
	    arphrd != ARPHRD_IEEE80211_RADIOTAP) {
		err(1, "Nu este activat modul monitor.\n");
	}
	
	kira_get_frequency(fd, devname, &freq);
	printf("Frecventa canalului este: %f \n", freq);
	
	kira_print_freq_info(fd, devname);
	
	kira_set_channel(fd, devname, 2);
	
	kira_get_frequency(fd, devname, &freq);
		printf("Frecventa canalului este: %f \n", freq);
	
	return 0;
	
	while ((len = kira_recv_packet(fd, buffer, sizeof(buffer)))) {
		if (len == -1) {
			usleep(sleep_time);
			continue;
		}
		memset(&current_packet, 0, sizeof(current_packet));
		if (!kira_parse_packet(buffer, len)) {
			DEBUG("nu am putut parsa pachetul!\n");
			continue;
		}
	}
	
	return 0;
}
