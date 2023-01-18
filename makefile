all: Sniffer Spoofer partC

Sniffer: Sniffer.o
	gcc -Wall -g -o Sniffer Sniffer.o -lpcap

Sniffer.o: Sniffer.c
	gcc -Wall -g -c Sniffer.c

Spoofer: Spoofer.o
	gcc -Wall -g -o Spoofer Spoofer.o

Spoofer.o: Spoofer.c
	gcc -Wall -g -c Spoofer.c

partC: partC.o
	gcc -Wall -g -o partC partC.o -lpcap

partC.o: partC.c
	gcc -Wall -g -c partC.c

clean:
	rm -f *.o Sniffer Spoofer 213205230_324239714.txt