#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ip.h> // for ip header
#include <netinet/tcp.h> // for tcp header

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

// Ethernet 헤더 구조체
struct EthernetHeader {
    u_char dst_mac[6];  // 대상 MAC 주소 (6바이트)
    u_char src_mac[6];  // 소스 MAC 주소 (6바이트)
    u_short ether_type; // Ethernet 타입 (2바이트)
};

void print_mac_addr(const u_char* mac_addr) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // Ethernet 헤더를 추출하여 출력
        printf("------------------------------------------------------------------------------\n");
        struct EthernetHeader* eth_header = (struct EthernetHeader*)packet;
        printf("Ethernet Header\n");
        printf("Src MAC: ");
        print_mac_addr(eth_header->src_mac);
        printf("  Dst MAC: ");
        print_mac_addr(eth_header->dst_mac);
        printf("\n\n");
      
        // IP 헤더를 추출하여 출력
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct EthernetHeader));
        printf("IP Header\n");
        printf("Src IP: %s  Dst IP: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
        printf("\n\n");
        
        // TCP 헤더를 추출하여 출력
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct EthernetHeader) + (ip_header->ip_hl << 2));
        printf("TCP Header\n");
        printf("Src Port: %u  Dst Port: %u", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
        printf("\n");
        
        // Payload(Data)의 hexadecimal value 출력
        const u_char* payload = packet + sizeof(struct EthernetHeader) + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);
        int payload_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2) - (tcp_header->th_off << 2);
        printf("Payload(Data) (Hexadecimal Value):\n");
        for (int i = 0; i < payload_len && i < 10; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
        printf("------------------------------------------------------------------------------\n\n\n");
    }

    pcap_close(pcap);
}
