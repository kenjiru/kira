OBJS=bin/kira.o bin/sniff.o

all: kira

kira: kira.o sniff.o
	$(CC) $(LDFLAGS) $(OBJS) -o bin/kira

kira.o:
	$(CC) $(CFLAGS) -c src/kira.c -o bin/kira.o
sniff.o:
	$(CC) $(CFLAGS) -c src/sniff.c -o bin/sniff.o

# remove object files and executable when user executes "make clean"
clean:
	rm *.o kira
