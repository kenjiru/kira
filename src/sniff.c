#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/wireless.h>
#include <err.h>
#include <pthread.h>

#include "sniff.h"
#include "util.h"

extern short current_channel;
extern pthread_mutex_t cj_mu;

int
kira_open_packet_socket(char* devname, 
		size_t 	bufsize,
		int 	recv_buffer_size)
{
	int fd;
	int ifindex;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		err(1, "nu am putut crea socketul\n");
	
	// determina id-ul interfetei wireless
	ifindex = kira_device_index(fd, devname);
	
	struct sockaddr_ll sall;
	sall.sll_ifindex = ifindex;
	sall.sll_family = AF_PACKET;
	sall.sll_protocol = htons(ETH_P_ALL);
	
	if (bind(fd, (struct sockaddr*)&sall, sizeof(sall)) != 0)
		err(1, "bind a esuat\n");
	
	kira_device_promisc(fd, devname, 1);
	kira_set_receive_buffer(fd, recv_buffer_size);

	return fd;
}

int
kira_device_index(int fd, 
		const char *devname)
{
	struct ifreq req;

	strncpy(req.ifr_name, devname, IFNAMSIZ);
	req.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFINDEX, &req) < 0)
		err(1, "nu am gasit interfata %s\n", devname);

	if (req.ifr_ifindex < 0) {
		err(1, "interface %s not found\n", devname);
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
		err(1, "nu am putut seta interfata %s\n", devname);
	}

	req.ifr_flags |= IFF_UP;

	if (on)
		req.ifr_flags |= IFF_PROMISC;
	else
		req.ifr_flags &= ~IFF_PROMISC;

	if (ioctl(fd, SIOCSIFFLAGS, &req) < 0) {
		err(1, "nu am putut seta modul promisc pentru interfata %s\n", devname);
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
		err(1, "nu am putut seta optiunile pentru socket\n");
}

int
kira_device_get_arptype(int fd, 
		const char *devname)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		err(1, "nu am putut determina tipul ARP\n");
	}
	DEBUG("ARPTYPE %d\n", ifr.ifr_hwaddr.sa_family);
	return ifr.ifr_hwaddr.sa_family;
}

inline int
kira_recv_packet(int fd, 
		unsigned char* buffer, 
		size_t bufsize)
{
	return recv(fd, buffer, bufsize, MSG_DONTWAIT);
}

int 
kira_get_frequency(int fd, 
		const char* devname, 
		double* freq) 
{ 
	struct iwreq wrq; 
	 
	// determina frecventa
	strncpy(wrq.ifr_name, devname, IFNAMSIZ);
	if(ioctl(fd, SIOCGIWFREQ, &wrq) < 0)
		err(1, "nu am putut determina frecventa canalului\n");
	
	*freq = kira_freq2float(wrq.u.freq);
	return 0; 
}

int 
kira_set_channel(int fd, 
		const char* devname, 
		short channel) 
{ 
	struct iwreq wrq; 
	struct iw_range	range;
	struct iw_freq freq;
	int	i;

	if(kira_get_range_info(fd, devname, &range) < 0)
		err(1, "nu am putut determina frecventele\n");
	
	if(channel > range.num_channels)
		err(1, "canal inexistent");
	
	// determina frecventa corespunzatoare canalului
	for(i = 0; i < range.num_frequency; i++)
		if(range.freq[i].i == channel) {
			freq = range.freq[i];  
		}
	 
	// seteaza frecventa
	wrq.u.freq = freq;
	wrq.u.freq.flags = IW_FREQ_FIXED;
	
	strncpy(wrq.ifr_name, devname, IFNAMSIZ);
	if(ioctl(fd, SIOCSIWFREQ, &wrq) < 0)
		err(1, "nu am putut seta frecventa canalului\n");

	return 0; 
} 

int
kira_get_range_info(int fd,
		const char *devname,
		struct iw_range *range)
{
	struct iwreq wrq;
	char buffer[sizeof(struct iw_range) * 2];

	wrq.u.data.pointer = (caddr_t) buffer;
	wrq.u.data.length = sizeof(buffer);
	wrq.u.data.flags = 0;
	
	strncpy(wrq.ifr_name, devname, IFNAMSIZ);
	if(ioctl(fd, SIOCGIWRANGE, &wrq) < 0)
		err(1, "nu am putut determina range-ul\n");
	
	memcpy((char *) range, buffer, sizeof(struct iw_range));
	
	DEBUG("range->we_version_compiled=%d\n", range->we_version_compiled);
	
	if(wrq.u.data.length < 300) {
		// versiune veche de wireless tools, mai veche de 10
		range->we_version_compiled = 9;
    }

	// daca versiunea e mai mica de 15, nu mergem mai departe
	if(range->we_version_compiled < 15) 
		err(1, "versiune wireless tools nesuportata\n");
	
	return 0;
}

int
kira_print_freq_info(int fd,
		char *devname)
{
	struct iw_range	range;
	
	double freq;
	int	i;
	char buffer[128];

	if(kira_get_range_info(fd, devname, &range) < 0)
		err(1, "nu am putut determina frecventele\n");
	
	DEBUG("range->num_channels=%d\n", range.num_channels);
	DEBUG("range->num_frequency=%d\n", range.num_frequency);
	
	if(range.num_frequency > 0) {
		printf("Sunt disponibile %d canale; avand frecventele:\n", range.num_channels);
		// afiseaza toate canalele si frecventele lor
		for(i = 0; i < range.num_frequency; i++) {
			freq = kira_freq2float(range.freq[i]);
			kira_print_freq_value(buffer, sizeof(buffer), freq);
			printf("canalul %.2d : %s\n", range.freq[i].i, buffer);
		}
	} 
	
	return 0;
}

void
kira_print_freq_value(char *buffer,
		int	buflen,
		double freq)
{
	if(freq < KILO)
		snprintf(buffer, buflen, "%g", freq);
	else {
		char	scale;
		int	divisor;

		if(freq >= GIGA) {
			scale = 'G';
			divisor = GIGA;
		} else {
			if(freq >= MEGA) {
				scale = 'M';
				divisor = MEGA;
			} else {
				scale = 'k';
				divisor = KILO;
			}
		}
		snprintf(buffer, buflen, "%g %cHz", freq / divisor, scale);
	}
}

double
kira_freq2float(struct iw_freq in)
{
	// varianta fara libm
	int		i;
	double	res = (double) in.m;
	
	for(i = 0; i < in.e; i++)
		res *= 10;
	
	return res;
}

void 
kira_jump_channels(void *thread_data)
{
	struct iwreq wrq; 
	struct iw_range	range;
	struct iw_freq freq;
	short num_channels;
	struct channel_jumper_data *data;  
	int fd;
	char *devname;
	int sleep_time = 3000000;
	int i;
	short channel = 0;
	
	data = (struct channel_jumper_data*) thread_data;
	fd = data->fd;
	devname = data->devname;

	if(kira_get_range_info(fd, devname, &range) < 0)
		err(1, "nu am putut determina frecventele\n");
	
	num_channels = range.num_channels;
	current_channel = 0;
	
	// schimbam canalele
	while(1) {
		DEBUG("schimbam canalul %d\n", channel);
		// incrementam canalul
		pthread_mutex_lock(&cj_mu);
		if(current_channel < num_channels)
			current_channel++;
		else
			current_channel = 1;
		channel = current_channel;
		pthread_mutex_unlock(&cj_mu);
		
		// determinam frecventa corespunzatoare canalului
		for(i = 0; i < range.num_frequency; i++)
			if(range.freq[i].i == channel) {
				freq = range.freq[i];  
			}
			 
		// setam frecventa
		wrq.u.freq = freq;
		wrq.u.freq.flags = IW_FREQ_FIXED;
		
		strncpy(wrq.ifr_name, devname, IFNAMSIZ);
		if(ioctl(fd, SIOCSIWFREQ, &wrq) < 0)
			err(1, "nu am putut seta frecventa canalului\n");
		
		usleep(sleep_time);
	}
}
