#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <err.h>
#include <pthread.h>

#include "sniff.h"
#include "parse.h"
#include "util.h"

// variabile globale
int arphrd;
struct packet_info current_packet;
short current_channel;
pthread_mutex_t cj_mu = PTHREAD_MUTEX_INITIALIZER;

int
main(int argc, char** argv)
{
	int fd;
	char* devname = "wlan0";
	int sleep_time = 1000;
	int recv_buffer_size = 6750000;
	unsigned char buffer[8192];
	int len, c;
	double freq;
	pthread_t cj_thread;
	struct channel_jumper_data cj_data;
	short cj_enabled = 1;
	short default_channel = 0;
	short print_channels = 0;
	
	DEBUG("modul DEBUG activat\n");
	
	while((c = getopt(argc, argv, "hpc:i:")) > 0) {
		switch (c) {
			case 'p':
				print_channels = 1;
				break;
			case 'i':
				devname = optarg;
				break;
			case 'c':
				default_channel = atoi(optarg);
				break;
			case 'h':
			default:
				printf("Utilizare: %s [-h] [-f] [-i interfata] [-c canal]\n\n"
					"Optiuni (valorile implicite):\n"
					"  -h\t\tacest mesaj de ajutor\n"
					"  -p\t\tafiseaza canalele suportate de placa\n"
					"  -i <interfata>\tinterfata (wlan0)\n"
					"  -c <canal>\tscaneaza doar canalul\n"
					"\n",
					argv[0]);
				exit(0);
				break;
		}
	}
	
	printf("Setarile sunt:\n");
	printf("\tcanalul: %d\n", default_channel);
	printf("\tinterfata: %s\n\n", devname);
	
	fd = kira_open_packet_socket(devname, sizeof(buffer), recv_buffer_size);
	if (fd < 0)
		err(1, "Nu am putut deschide socketul\n");
	
	arphrd = kira_device_get_arptype(fd, devname);
	if (arphrd != ARPHRD_IEEE80211_PRISM &&
	    arphrd != ARPHRD_IEEE80211_RADIOTAP) {
		err(1, "Nu este activat modul monitor.\n");
	}
	
	if(print_channels) {
		kira_print_freq_info(fd, devname);
		return 0;
	}
	
	if(default_channel)
		// scanam un singur canal
		kira_set_channel(fd, devname, default_channel);
	else {
		// scanam toate canalele suportate de placa
		cj_data.devname = devname;
		cj_data.fd = fd;
		pthread_create(&cj_thread, NULL, kira_jump_channels, (void *) &cj_data);
	}
	
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
