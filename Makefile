all: pcap_test

pcap_test : main.cpp
	g++ -o pcap_test main.cpp -lpcap

clean:
	rm -f pcap-test *.o
