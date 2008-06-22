#ifndef SNIFF_H_
#define SNIFF_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/wireless.h>

#define ARPHRD_IEEE80211_RADIOTAP 803    /* IEEE 802.11 + radiotap header */
#define ARPHRD_IEEE80211_PRISM 802      /* IEEE 802.11 + Prism2 header  */

int
kira_open_packet_socket(char* devname, size_t bufsize, int recv_buffer_size);

#endif /*SNIFF_H_*/
