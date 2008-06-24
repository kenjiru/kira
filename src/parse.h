#ifndef PARSE_H_
#define PARSE_H_

#include <sys/types.h>

#define MAC_LEN			6

#define MAX_NODES		255
#define MAX_ESSIDS		255
#define MAX_BSSIDS		255
#define MAX_HISTORY		255
#define MAX_ESSID_LEN		255
#define MAX_RATES		109	/* in 500kbps steps: 54 * 2 + 1 for array index */
#define MAX_FSTYPE		0xff
#define MAX_FILTERMAC		9

/* packet types we actually care about, e.g filter */
#define PKT_TYPE_CTRL		0x000001
#define PKT_TYPE_MGMT		0x000002
#define PKT_TYPE_DATA		0x000004

#define PKT_TYPE_BEACON		0x000010
#define PKT_TYPE_PROBE		0x000020
#define PKT_TYPE_ASSOC		0x000040
#define PKT_TYPE_AUTH		0x000080
#define PKT_TYPE_RTS		0x000100
#define PKT_TYPE_CTS		0x000200
#define PKT_TYPE_ACK		0x000400
#define PKT_TYPE_NULL		0x000800

#define PKT_TYPE_ARP		0x001000
#define PKT_TYPE_IP		0x002000
#define PKT_TYPE_ICMP		0x004000
#define PKT_TYPE_UDP		0x008000
#define PKT_TYPE_TCP		0x010000
#define PKT_TYPE_OLSR		0x020000
#define PKT_TYPE_OLSR_LQ	0x040000
#define PKT_TYPE_OLSR_GW	0x080000
#define PKT_TYPE_BATMAN		0x100000

#define PKT_TYPE_ALL_MGMT	(PKT_TYPE_BEACON | PKT_TYPE_PROBE | PKT_TYPE_ASSOC | PKT_TYPE_AUTH)
#define PKT_TYPE_ALL_CTRL	(PKT_TYPE_RTS | PKT_TYPE_CTS | PKT_TYPE_ACK)
#define PKT_TYPE_ALL_DATA	(PKT_TYPE_NULL | PKT_TYPE_ARP | PKT_TYPE_ICMP | PKT_TYPE_IP | \
				 PKT_TYPE_UDP | PKT_TYPE_TCP | PKT_TYPE_OLSR | PKT_TYPE_OLSR_LQ | \
				 PKT_TYPE_OLSR_GW | PKT_TYPE_BATMAN)

#define WLAN_MODE_AP		0x01
#define WLAN_MODE_IBSS		0x02
#define WLAN_MODE_STA		0x04
#define WLAN_MODE_PROBE		0x08

#define PHY_FLAG_SHORTPRE	0x0001
#define PHY_FLAG_A		0x0010
#define PHY_FLAG_B		0x0020
#define PHY_FLAG_G		0x0040
#define PHY_FLAG_MODE_MASK	0x00f0

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803    /* IEEE 802.11 + radiotap header */
#endif

#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802      /* IEEE 802.11 + Prism2 header  */
#endif

struct packet_info {
	/* general */
	int			pkt_types;	/* bitmask of packet types in this pkt */
	int			len;		/* packet length */

	/* wlan phy (from radiotap) */
	int			signal;		/* signal strength (usually dBm) */
	int			noise;		/* noise level (usually dBm) */
	int			snr;		/* signal to noise ratio */
	int			rate;		/* physical rate */
	int			phy_freq;	/* frequency (unused) */
	int			phy_flags;	/* A, B, G, shortpre */

	/* wlan mac */
	int					wlan_type;	/* frame control field */
	unsigned char		wlan_src[MAC_LEN];
	unsigned char		wlan_dst[MAC_LEN];
	unsigned char		wlan_bssid[MAC_LEN];
	char				wlan_essid[255];
	u_int64_t			wlan_tsf;	/* timestamp from beacon */
	int					wlan_mode;	/* AP, STA or IBSS */
	unsigned char		wlan_channel;	/* channel from beacon, probe */
	int					wlan_wep;	/* WEP on/off */

	/* IP */
	unsigned int		ip_src;
	unsigned int		ip_dst;
	int					olsr_type;
	int					olsr_neigh;
	int					olsr_tc;
};

int
kira_parse_80211_header(unsigned char** buf, 
		int len);

int
kira_parse_ip_header(unsigned char** buf, 
		int len);

inline int
kira_parse_llc(unsigned char ** buf, 
		int len);

int
kira_parse_packet(unsigned char* buf, 
		int len);

int
kira_parse_prism_header(unsigned char** buf, 
		int len);

int
kira_parse_radiotap_header(unsigned char** buf, 
		int len);

#endif /*PARSE_H_*/
