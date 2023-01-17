all: Sniffer Spoofer

Sniffer: Sniffer.o
	gcc -Wall -g -o Sniffer Sniffer.o -lpcap

Sniffer.o: Sniffer.c
	gcc -Wall -g -c Sniffer.c

Spoofer: Spoofer.o
	gcc -Wall -g -o Spoofer Spoofer.o

Spoofer.o: Spoofer.c
	gcc -Wall -g -c Spoofer.c

clean:
	rm -f *.o Sniffer Spoofer part1.txt