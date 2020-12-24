all:
	gcc 1220test.c -o pcap.exe -lpcap
clean:
	rm -f pcap.exe

exe:
	./pcap.exe

vim:
	vim 1220test.c
