#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "kira.h"
#include "parse.h"
#include "util.h"

#include "prism_header.h"
#include "ieee80211_radiotap.h"
#include "ieee80211.h"
#include "ieee80211_util.h"

int
kira_parse_packet(unsigned char* buf, int len)
{
	if (arphrd == ARPHRD_IEEE80211_PRISM) {
		len = kira_parse_prism_header(&buf, len);
		if (len <= 0)
			return 0;
	}
	else if (arphrd == ARPHRD_IEEE80211_RADIOTAP) {
		len = kira_parse_radiotap_header(&buf, len);
		if (len <= 0)
			return 0;
	}

	if (arphrd == ARPHRD_IEEE80211 ||
	    arphrd == ARPHRD_IEEE80211_PRISM ||
	    arphrd == ARPHRD_IEEE80211_RADIOTAP) {
		DEBUG("before parse 80211 len: %d\n", len);
		len = kira_parse_80211_header(&buf, len);
		if (len < 0) // couldnt parse 
			return 0;
		else if (len == 0)
			return 1;
	}

	len = kira_parse_llc(&buf, len);
	if (len <= 0)
		return 1;

	len = kira_parse_ip_header(&buf, len);
	if (len <= 0)
		return 1;

	return 1;
}

int
kira_parse_prism_header(unsigned char** buf, int len)
{
	wlan_ng_prism2_header* ph;

	DEBUG("PRISM2 HEADER\n");

	if (len < sizeof(wlan_ng_prism2_header))
		return -1;

	ph = (wlan_ng_prism2_header*)*buf;

	/*
	 * different drivers report S/N and rssi values differently
	 * let's make sure here that SNR is always positive, so we
	 * don't have do handle special cases later
	*/
	if (((int)ph->noise.data) < 0) {
		/* new madwifi */
		current_packet.signal = ph->signal.data;
		current_packet.noise = ph->noise.data;
		current_packet.snr = ph->rssi.data;
	}
	else if (((int)ph->rssi.data) < 0) {
		/* broadcom hack */
		current_packet.signal = ph->rssi.data;
		current_packet.noise = -95;
		current_packet.snr = 95 + ph->rssi.data;
	}
	else {
		/* assume hostap */
		current_packet.signal = ph->signal.data;
		current_packet.noise = ph->noise.data;
		current_packet.snr = ph->signal.data - ph->noise.data; //XXX rssi?
	}

	current_packet.rate = ph->rate.data;

	/* just in case...*/
	if (current_packet.snr < 0)
		current_packet.snr = -current_packet.snr;
	if (current_packet.snr > 99)
		current_packet.snr = 99;
	if (current_packet.rate == 0 || current_packet.rate > 108) {
		/* assume min rate, guess mode from channel */
		DEBUG("*** fixing wrong rate\n");
		if (ph->channel.data > 14)
			current_packet.rate = 12; /* 6 * 2 */
		else
			current_packet.rate = 2; /* 1 * 2 */
	}

	/* guess phy mode */
	if (ph->channel.data > 14)
		current_packet.phy_flags |= PHY_FLAG_A;
	else
		current_packet.phy_flags |= PHY_FLAG_G;
	/* always assume shortpre */
	current_packet.phy_flags |= PHY_FLAG_SHORTPRE;

	DEBUG("devname: %s\n", ph->devname);
	DEBUG("signal: %d -> %d\n", ph->signal.data, current_packet.signal);
	DEBUG("noise: %d -> %d\n", ph->noise.data, current_packet.noise);
	DEBUG("rate: %d\n", ph->rate.data);
	DEBUG("rssi: %d\n", ph->rssi.data);
	DEBUG("*** SNR %d\n", current_packet.snr);

	*buf = *buf + sizeof(wlan_ng_prism2_header);
	return len - sizeof(wlan_ng_prism2_header);
}

int
kira_parse_radiotap_header(unsigned char** buf, int len)
{
	struct ieee80211_radiotap_header* rh;
	__le32 present; /* the present bitmap */
	unsigned char* b; /* current byte */
	int i;

	DEBUG("RADIOTAP HEADER\n");

	DEBUG("len: %d\n", len);

	if (len < sizeof(struct ieee80211_radiotap_header))
		return -1;

	rh = (struct ieee80211_radiotap_header*)*buf;
	b = *buf + sizeof(struct ieee80211_radiotap_header);
	present = rh->it_present;

	DEBUG("%08x\n", present);

	/* check for header extension - ignore for now, just advance current position */
	while (present & 0x80000000  && b - *buf < rh->it_len) {
		DEBUG("extension\n");
		b = b + 4;
		present = *(__le32*)b;
	}
	present = rh->it_present; // in case it moved

	/* radiotap bitmap has 32 bit, but we are only interrested until
	 * bit 12 (IEEE80211_RADIOTAP_DB_ANTSIGNAL) => i<13 */
	for (i = 0; i < 13 && b - *buf < rh->it_len; i++) {
		if ((present >> i) & 1) {
			DEBUG("1");
			switch (i) {
				/* just ignore the following (advance position only) */
				case IEEE80211_RADIOTAP_TSFT:
					DEBUG("[+8]");
					b = b + 8;
					break;
				case IEEE80211_RADIOTAP_DBM_TX_POWER:
				case IEEE80211_RADIOTAP_ANTENNA:
				case IEEE80211_RADIOTAP_RTS_RETRIES:
				case IEEE80211_RADIOTAP_DATA_RETRIES:
					DEBUG("[+1]");
					b++;
					break;
				case IEEE80211_RADIOTAP_EXT:
					DEBUG("[+4]");
					b = b + 4;
					break;
				case IEEE80211_RADIOTAP_FHSS:
				case IEEE80211_RADIOTAP_LOCK_QUALITY:
				case IEEE80211_RADIOTAP_TX_ATTENUATION:
				case IEEE80211_RADIOTAP_RX_FLAGS:
				case IEEE80211_RADIOTAP_TX_FLAGS:
				case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
					DEBUG("[+2]");
					b = b + 2;
					break;
				/* we are only interrested in these: */
				case IEEE80211_RADIOTAP_RATE:
					DEBUG("[rate %0x]", *b);
					current_packet.rate = (*b);
					b++;
					break;
				case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
					DEBUG("[sig %0x]", *b);
					current_packet.signal = *(char*)b;
					b++;
					break;
				case IEEE80211_RADIOTAP_DBM_ANTNOISE:
					DEBUG("[noi %0x]", *b);
					current_packet.noise = *(char*)b;
					b++;
					break;
				case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
					DEBUG("[snr %0x]", *b);
					current_packet.snr = *b;
					b++;
					break;
				case IEEE80211_RADIOTAP_FLAGS:
					/* short preamble */
					DEBUG("[flags %0x", *b);
					if (*b & IEEE80211_RADIOTAP_F_SHORTPRE) {
						current_packet.phy_flags |= PHY_FLAG_SHORTPRE;
						DEBUG(" shortpre");
					}
					DEBUG("]");
					b++;
					break;
				case IEEE80211_RADIOTAP_CHANNEL:
					/* channel & channel type */
					current_packet.phy_freq = *(u_int16_t*)b;
					DEBUG("[chan %d ", current_packet.phy_freq);
					b = b + 2;
					if (*(u_int16_t*)b & IEEE80211_CHAN_A) {
						current_packet.phy_flags |= PHY_FLAG_A;
						DEBUG("A]");
					}
					else if (*(u_int16_t*)b & IEEE80211_CHAN_G) {
						current_packet.phy_flags |= PHY_FLAG_G;
						DEBUG("G]");
					}
					else if (*(u_int16_t*)b & IEEE80211_CHAN_B) {
						current_packet.phy_flags |= PHY_FLAG_B;
						DEBUG("B]");
					}
					b = b + 2;
					break;
			}
		}
		else {
			DEBUG("0");
		}
	}
	DEBUG("\n");

	/* sanitize */
	if (current_packet.snr > 99)
		current_packet.snr = 99;
	if (current_packet.rate == 0 || current_packet.rate > 108) {
		/* assume min rate for mode */
		DEBUG("*** fixing wrong rate\n");
		if (current_packet.phy_flags & PHY_FLAG_A)
			current_packet.rate = 12; /* 6 * 2 */
		else if (current_packet.phy_flags & PHY_FLAG_B)
			current_packet.rate = 2; /* 1 * 2 */
		else if (current_packet.phy_flags & PHY_FLAG_G)
			current_packet.rate = 12; /* 6 * 2 */
		else
			current_packet.rate = 2;
	}

	DEBUG("\nrate: %d\n", current_packet.rate);
	DEBUG("signal: %d\n", current_packet.signal);
	DEBUG("noise: %d\n", current_packet.noise);
	DEBUG("snr: %d\n", current_packet.snr);

	*buf = *buf + rh->it_len;
	return len - rh->it_len;
}

int
kira_parse_80211_header(unsigned char** buf, int len)
{
	struct ieee80211_hdr* wh;
	struct ieee80211_mgmt* whm;
	int hdrlen;
	u8* sa = NULL;
	u8* da = NULL;
	u8* bssid = NULL;

	if (len < 2) /* not even enough space for fc */
		return -1;

	wh = (struct ieee80211_hdr*)*buf;
	hdrlen = kira_ieee80211_get_hdrlen(wh->frame_control);

	if (len < hdrlen)
		return -1;

	current_packet.len = len;
	current_packet.wlan_type = (wh->frame_control & (IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE));

	DEBUG("wlan_type %x - type %x - stype %x\n", wh->frame_control, wh->frame_control & IEEE80211_FCTL_FTYPE, wh->frame_control & IEEE80211_FCTL_STYPE );

	DEBUG("%s\n", get_packet_type_name(wh->frame_control));

	bssid = kira_ieee80211_get_bssid(wh, len);

	switch (current_packet.wlan_type & IEEE80211_FCTL_FTYPE) {
	case IEEE80211_FTYPE_DATA:
		current_packet.pkt_types = PKT_TYPE_DATA;
		switch (current_packet.wlan_type & IEEE80211_FCTL_STYPE) {
		case IEEE80211_STYPE_NULLFUNC:
			current_packet.pkt_types |= PKT_TYPE_NULL;
			break;
		}
		sa = ieee80211_get_SA(wh);
		da = ieee80211_get_DA(wh);
		/* AP, STA or IBSS */
		if ((wh->frame_control & IEEE80211_FCTL_FROMDS) == 0 &&
		(wh->frame_control & IEEE80211_FCTL_TODS) == 0)
			current_packet.wlan_mode = WLAN_MODE_IBSS;
		else if (wh->frame_control & IEEE80211_FCTL_FROMDS)
			current_packet.wlan_mode = WLAN_MODE_AP;
		else if (wh->frame_control & IEEE80211_FCTL_TODS)
			current_packet.wlan_mode = WLAN_MODE_STA;
		/* WEP */
		if (wh->frame_control & IEEE80211_FCTL_PROTECTED)
			current_packet.wlan_wep = 1;
		break;

	case IEEE80211_FTYPE_CTL:
		current_packet.pkt_types = PKT_TYPE_CTRL;
		switch (current_packet.wlan_type & IEEE80211_FCTL_STYPE) {
		case IEEE80211_STYPE_RTS:
			current_packet.pkt_types |= PKT_TYPE_RTS;
			sa = wh->addr2;
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_CTS:
			current_packet.pkt_types |= PKT_TYPE_CTS;
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_ACK:
			current_packet.pkt_types |= PKT_TYPE_ACK;
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_PSPOLL:
			sa = wh->addr2;
			break;

		case IEEE80211_STYPE_CFEND:
			da = wh->addr1;
			sa = wh->addr2;
			break;

		case IEEE80211_STYPE_CFENDACK:
			/* dont know, dont care */
			break;
		}
		break;

	case IEEE80211_FTYPE_MGMT:
		current_packet.pkt_types = PKT_TYPE_MGMT;
		whm = (struct ieee80211_mgmt*)*buf;
		sa = whm->sa;
		da = whm->da;

		switch (current_packet.wlan_type & IEEE80211_FCTL_STYPE) {
		case IEEE80211_STYPE_BEACON:
			current_packet.pkt_types |= PKT_TYPE_BEACON;
			current_packet.wlan_tsf = whm->u.beacon.timestamp;
			kira_ieee802_11_parse_elems(whm->u.beacon.variable,
				len - sizeof(struct ieee80211_mgmt) - 4 /* FCS */, &current_packet);
			DEBUG("ESSID %s \n", current_packet.wlan_essid );
			DEBUG("CHAN %d \n", current_packet.wlan_channel );
			if (whm->u.beacon.capab_info & WLAN_CAPABILITY_IBSS)
				current_packet.wlan_mode = WLAN_MODE_IBSS;
			else if (whm->u.beacon.capab_info & WLAN_CAPABILITY_ESS)
				current_packet.wlan_mode = WLAN_MODE_AP;
			if (whm->u.beacon.capab_info & WLAN_CAPABILITY_PRIVACY)
				current_packet.wlan_wep = 1;
			break;

		case IEEE80211_STYPE_PROBE_RESP:
			current_packet.pkt_types |= PKT_TYPE_PROBE;
			current_packet.wlan_tsf = whm->u.beacon.timestamp;
			kira_ieee802_11_parse_elems(whm->u.beacon.variable,
				len - sizeof(struct ieee80211_mgmt) - 4 /* FCS */, &current_packet);
			DEBUG("ESSID %s \n", current_packet.wlan_essid );
			DEBUG("CHAN %d \n", current_packet.wlan_channel );
			if (whm->u.beacon.capab_info & WLAN_CAPABILITY_IBSS)
				current_packet.wlan_mode = WLAN_MODE_IBSS;
			else if (whm->u.beacon.capab_info & WLAN_CAPABILITY_ESS)
				current_packet.wlan_mode = WLAN_MODE_AP;
			if (whm->u.beacon.capab_info & WLAN_CAPABILITY_PRIVACY)
				current_packet.wlan_wep = 1;
			break;

		case IEEE80211_STYPE_PROBE_REQ:
			current_packet.pkt_types |= PKT_TYPE_PROBE;
			kira_ieee802_11_parse_elems(whm->u.probe_req.variable,
				len - 24 - 4 /* FCS */,
				&current_packet);
			current_packet.wlan_mode |= WLAN_MODE_PROBE;
			break;

		case IEEE80211_STYPE_ASSOC_REQ:
		case IEEE80211_STYPE_ASSOC_RESP:
		case IEEE80211_STYPE_REASSOC_REQ:
		case IEEE80211_STYPE_REASSOC_RESP:
		case IEEE80211_STYPE_DISASSOC:
			current_packet.pkt_types |= PKT_TYPE_ASSOC;
			break;

		case IEEE80211_STYPE_AUTH:
		case IEEE80211_STYPE_DEAUTH:
			current_packet.pkt_types |= PKT_TYPE_AUTH;
			break;
		}
		break;
	}

	if (sa != NULL) {
		memcpy(current_packet.wlan_src, sa, MAC_LEN);
		DEBUG("SA    %s\n", ether_sprintf(sa));
	}
	if (da != NULL) {
		memcpy(current_packet.wlan_dst, da, MAC_LEN);
		DEBUG("DA    %s\n", ether_sprintf(da));
	}
	if (bssid!=NULL) {
		memcpy(current_packet.wlan_bssid, bssid, MAC_LEN);
		DEBUG("BSSID %s\n", ether_sprintf(bssid));
	}

	/* only data frames contain more info, otherwise stop parsing */
	if ((current_packet.wlan_type & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA &&
	     current_packet.wlan_wep != 1) {
		*buf = *buf + hdrlen;
		return len - hdrlen;
	}
	return 0;
}


inline int
kira_parse_llc(unsigned char ** buf, int len)
{
	DEBUG("* parse LLC\n");

	if (len < 6)
		return -1;

	// check type in LLC header 
	*buf = *buf + 6;
	if (**buf != 0x08)
		return -1;
	(*buf)++;
	if (**buf == 0x06) { // ARP 
		current_packet.pkt_types |= PKT_TYPE_ARP;
		return 0;
	}
	if (**buf != 0x00)  // not IP 
		return -1;
	(*buf)++;

	DEBUG("* parse LLC left %d\n", len - 8);

	return len - 8;
}


int
kira_parse_ip_header(unsigned char** buf, int len)
{
	struct iphdr* ih;

	DEBUG("* parse IP\n");

	if (len < sizeof(struct iphdr))
		return -1;

	ih = (struct iphdr*)*buf;

	DEBUG("*** IP SRC: %s\n", ip_sprintf(ih->saddr));
	DEBUG("*** IP DST: %s\n", ip_sprintf(ih->daddr));
	current_packet.ip_src = ih->saddr;
	current_packet.ip_dst = ih->daddr;
	current_packet.pkt_types |= PKT_TYPE_IP;

	DEBUG("IP proto: %d\n", ih->protocol);
	switch (ih->protocol) {
	case IPPROTO_UDP: current_packet.pkt_types |= PKT_TYPE_UDP; break;
	// all others set the type and return. no more parsing 
	case IPPROTO_ICMP: current_packet.pkt_types |= PKT_TYPE_ICMP; return 0;
	case IPPROTO_TCP: current_packet.pkt_types |= PKT_TYPE_TCP; return 0;
	}


	*buf = *buf + ih->ihl * 4;
	return len - ih->ihl * 4;
}
