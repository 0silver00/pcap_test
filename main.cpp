#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include "libnet-headers.h"

#define SIZE_ETHERNET 14

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;

        const struct libnet_ethernet_hdr* ether_packet;
        const struct libnet_ipv4_hdr* ipv4_packet;
        const struct libnet_tcp_hdr* tcp_packet;
        const char* payload;

        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;  
        }

        //printf("%u bytes captured\n", header->caplen);

        ether_packet = (struct libnet_ethernet_hdr*)(packet);
        ipv4_packet = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);

        tcp_packet = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + 20);

        payload = (char *)(packet + SIZE_ETHERNET + 20 + 20);

        printf("################################################################\n");
        printf("**Ethernet**\n");
        printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
               ether_packet->ether_dhost[0],ether_packet->ether_dhost[2],
                ether_packet->ether_dhost[4],ether_packet->ether_dhost[6],
                ether_packet->ether_dhost[8],ether_packet->ether_dhost[10]);
        printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n\n",
               ether_packet->ether_shost[0],ether_packet->ether_shost[2],
                ether_packet->ether_shost[4],ether_packet->ether_shost[6],
                ether_packet->ether_shost[8],ether_packet->ether_shost[10]);

        printf("*****IP*****\n");
        printf("src ip : %s\n", inet_ntoa(ipv4_packet->ip_src));
        printf("dst ip : %s\n\n", inet_ntoa(ipv4_packet->ip_dst));

        printf("****TCP*****\n");
        printf("src port : %d\n", ntohs(tcp_packet->th_sport));
        printf("dst port : %d\n\n", ntohs(tcp_packet->th_dport));

        printf("****data****\n");
        printf("%s\n\n\n", payload);

    }
    pcap_close(handle);
}
