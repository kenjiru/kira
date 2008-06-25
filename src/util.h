#ifndef UTIL_H_
#define UTIL_H_

#define VERSION "0.1"

#ifndef DO_DEBUG
#define DO_DEBUG 1
#endif

#if DO_DEBUG
#define DEBUG(...) printf(__VA_ARGS__)
#else
#define DEBUG(...)
#endif

#define DATA_NAME_INDEX(_i) (((_i) & IEEE80211_FCTL_STYPE)>>4)
#define MGMT_NAME_INDEX(_i) (((_i) & IEEE80211_FCTL_STYPE)>>4)
#define CTRL_NAME_INDEX(_i) ((((_i) & IEEE80211_FCTL_STYPE)>>4)-10)

// macrouri folositoare
#define MAC_NOT_EMPTY(_mac) (_mac[0] || _mac[1] || _mac[2] || _mac[3] || _mac[4] || _mac[5])
#define MAC_EMPTY(_mac) (!_mac[0] && !_mac[1] && !_mac[2] && !_mac[3] && !_mac[4] && !_mac[5])
#define TOGGLE_BIT(_x, _m) (_x) = (_x) & (_m) ? (_x) & ~(_m) : (_x) | (_m)

struct pkt_names {
	char c;
	const char* name;
};

void
dump_packet(const unsigned char* buf, 
		int len);

const char*
ether_sprintf(const unsigned char *mac);

const char*
ip_sprintf(const unsigned int ip);

void
convert_string_to_mac(const char* string, 
		unsigned char* mac);

inline int
normalize(float val, 
		int max_val, 
		int max);

#define normalize_db(_val, _max) \
	normalize((_val) - 30, 70, (_max))

char
get_packet_type_char(int type);

const char*
get_packet_type_name(int type);

const char*
kilo_mega_ize(unsigned int val);

#endif /*UTIL_H_*/
