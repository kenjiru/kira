#ifndef SNIFF_H_
#define SNIFF_H_

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

double
kira_freq2float(struct iw_freq in);

#endif /*SNIFF_H_*/
