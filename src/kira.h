#ifndef KIRA_H_
#define KIRA_H_

#include "parse.h"

#define VERSION "0.1"

#ifndef DO_DEBUG
#define DO_DEBUG 0
#endif

#if DO_DEBUG
#define DEBUG(...) printf(__VA_ARGS__)
#else
#define DEBUG(...)
#endif

// variabile globale
int arphrd;
int mon_fd;
char* mon_ifname;
struct packet_info current_packet;

// variabile de configurare
char* ifname; // interfata wireless
int recv_buffer_size; // dim. bufferului
int sleep_time; // refresh-ul

#endif /*KIRA_H_*/
