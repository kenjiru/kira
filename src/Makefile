NAME=kira
LIBS=-lpthread
OBJS=kira.o sniff.o parse.o util.o ieee80211_util.o
# this Makefile is for OpenWrt build
all:kira

kira: kira.o sniff.o parse.o util.o ieee80211_util.o
	$(CC) $(LDFLAGS) -o kira $(OBJS) $(LIBS)

kira.o:
	$(CC) $(CFLAGS) -c kira.c
sniff.o:
	$(CC) $(CFLAGS) -c sniff.c
ieee80211_util.o: 
	$(CC) $(CFLAGS) -c ieee80211_util.c
parse.o:
	$(CC) $(CFLAGS) -c parse.c
util.o:
	$(CC) $(CFLAGS) -c util.c

# remove object files and executable when user executes "make clean"
clean:
	rm *.o kira
