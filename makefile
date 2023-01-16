all: Sniffer

Sniffer: Sniffer.o
	gcc -Wall -g -o Sniffer Sniffer.o -lpcap

Sniffer.o: Sniffer.c
	gcc -Wall -g -c Sniffer.c

clean:
	rm -f *.o Sniffer