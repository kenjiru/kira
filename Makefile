NAME=kira
LIBS=-lpthread
OBJS=bin/kira.o bin/sniff.o bin/ieee80211_util.o bin/parse.o bin/util.o

all: kira

kira: $(OBJS)
	$(CC) $(LDFLAGS) -o bin/kira $(OBJS) $(LIBS)

bin/kira.o:
	$(CC) $(CFLAGS) -c src/kira.c -o bin/kira.o
bin/sniff.o:
	$(CC) $(CFLAGS) -c src/sniff.c -o bin/sniff.o
bin/ieee80211_util.o: 
	$(CC) $(CFLAGS) -c src/ieee80211_util.c -o bin/ieee80211_util.o
bin/parse.o:
	$(CC) $(CFLAGS) -c src/parse.c -o bin/parse.o
bin/util.o:
	$(CC) $(CFLAGS) -c src/util.c -o bin/util.o


# remove object files and executable when user executes "make clean"
clean:
	rm bin/*.o bin/kira
