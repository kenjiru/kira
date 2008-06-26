#ifndef SNIFF_H_
#define SNIFF_H_

// cateva constante utile
#define KILO	1e3
#define MEGA	1e6
#define GIGA	1e9

struct channel_jumper_data {
	int fd;
	char* devname;
};

int
kira_open_packet_socket(char* devname, 
		size_t 	bufsize,
		int 	recv_buffer_size);

int
kira_device_index(int fd, 
		const char *devname);

void
kira_device_promisc(int fd, 
		const char *devname, 
		int on);

void
kira_set_receive_buffer(int fd, 
		int sockbufsize);

int
kira_device_get_arptype(int fd, 
		const char *devname);

inline int
kira_recv_packet(int fd, 
		unsigned char* buffer, 
		size_t bufsize);

int 
kira_get_frequency(int fd, 
		const char* devname, 
		double* freq);

int 
kira_set_channel(int fd, 
		const char* devname, 
		short channel);

double
kira_freq2float(struct iw_freq in);

int
kira_get_range_info(int fd,
		const char *devname,
		struct iw_range *range);

int
kira_print_freq_info(int fd,
		char *devname);

void
kira_print_freq_value(char *buffer,
		int	buflen,
		double freq);

void 
kira_jump_channels(void *thread_data);

#endif /*SNIFF_H_*/
