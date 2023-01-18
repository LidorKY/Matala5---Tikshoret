all: partC

partC: partC.o
	gcc -Wall -g -o partC partC.o -lpcap

partC.o: partC.c
	gcc -Wall -g -c partC.c

clean:
	rm -f *.o partC
