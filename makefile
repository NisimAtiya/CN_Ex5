all: sniffer spoofer

spoofer: spoofer.c
	gcc -o spoofer spoofer.c

sniffer: sniffer.c
	gcc -o sniffer sniffer.c -lpcap

clean:
	rm -f spoofer sniffer *.txt