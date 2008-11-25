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

void 
kira_print_packet_info(unsigned char* ign_sa, 
		unsigned char* ign_da, 
		unsigned char* ign_bssid);

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
	unsigned char ign_sa[MAC_LEN], ign_da[MAC_LEN], ign_bssid[MAC_LEN];
	
	DEBUG("modul DEBUG activat\n");
	
	while((c = getopt(argc, argv, "hpc:i:d:s:b:")) > 0) {
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
			case 'd':
				convert_string_to_mac(optarg, ign_da);
				printf("ignore DA %s\n", ether_sprintf(ign_da));
				break;
			case 's':
				convert_string_to_mac(optarg, ign_sa);
				printf("ignore SA %s\n", ether_sprintf(ign_sa));
				break;
			case 'b':
				convert_string_to_mac(optarg, ign_bssid);
				printf("ignore BSSID %s\n", ether_sprintf(ign_bssid));
				break;
			case 'h':
			default:
				printf("Utilizare: %s [-h] [-f] [-i interfata] [-c canal] [-d MAC] [-s MAC] [-b MAC]\n\n"
					"Optiuni (valorile implicite):\n"
					"  -h\t\t acest mesaj de ajutor\n"
					"  -p\t\t afiseaza canalele suportate de placa\n"
					"  -i <interfata>\t interfata (wlan0)\n"
					"  -c <canal>\t scaneaza doar canalul\n"
					"  -d <MAC>\t ignora MAC-ul destinatie\n"
					"  -s <MAC>\t ignora MAC-ul sursa\n"
					"  -b <MAC>\t ignora BSSID\n"
					"\n",
					argv[0]);
				exit(0);
				break;
		}
	}
	
	printf("Setarile sunt:\n");
	printf("\t canalul: %d\n", default_channel);
	printf("\t interfata: %s\n\n", devname);
	
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
		
		// afisam informatii despre pachet
#if !DO_DEBUG
		kira_print_packet_info(ign_sa, ign_da, ign_bssid);
#endif
		
		DEBUG("\n");
	}
	
	return 0;
}

void 
kira_print_packet_info(unsigned char* ign_sa, 
		unsigned char* ign_da, 
		unsigned char* ign_bssid)
{
	// verific daca trebuie sa ignor vre-un pachet
	if((ign_sa != NULL && current_packet.wlan_src != NULL && memcmp(current_packet.wlan_src,ign_sa, MAC_LEN) == 0) ||
		(ign_da != NULL && current_packet.wlan_dst != NULL && memcmp(current_packet.wlan_dst,ign_da, MAC_LEN) == 0) || 
		(ign_bssid != NULL && current_packet.wlan_bssid != NULL && memcmp(current_packet.wlan_bssid,ign_bssid, MAC_LEN) == 0)) {
		return;
	}
	
	// afiseaza informatii despre pachet
	printf("tipul pachetului: %s \n", 
		get_packet_type_name(current_packet.wlan_type));
	// TODO: sa afisez ESSID-ul
//	if(current_packet.wlan_essid != NULL)
//		printf("ESSID %s \n", current_packet.wlan_essid);
	if(current_packet.wlan_channel != NULL)
		printf("CHAN %d \n", current_packet.wlan_channel);
	if(current_packet.wlan_src != NULL)
		printf("SA    %s\n", ether_sprintf(current_packet.wlan_src));
	if(current_packet.wlan_dst != NULL)
		printf("DA    %s\n", ether_sprintf(current_packet.wlan_dst));
	if(current_packet.wlan_bssid != NULL)
		printf("BSSID    %s\n", ether_sprintf(current_packet.wlan_bssid));
	if(current_packet.ip_src != NULL)
		printf("IP SRC	%s\n", ip_sprintf(current_packet.ip_src));
	if(current_packet.ip_dst != NULL)
		printf("IP DST	%s\n", ip_sprintf(current_packet.ip_dst));
	printf("\n");
}
