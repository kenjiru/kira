#ifndef KIRA_H_
#define KIRA_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <err.h>

#ifndef DO_DEBUG
#define DO_DEBUG 1
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

// variabile de configurare
static char* ifname = "wlan0"; // interfata wireless
static int recv_buffer_size = 6750000; // dim. bufferului
static int sleep_time = 1000;

#endif /*KIRA_H_*/
