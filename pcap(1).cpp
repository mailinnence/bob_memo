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
// 이더넷(Ethernet)은 주로 현대 컴퓨터 네트워크에서 가장 널리 사용되는 유선 네트워크 기술
// 이더넷은 컴퓨터들 간에 데이터를 주고받을 수 있게 해주는 통신 프로토콜
// 이더넷 프레임(Ethernet Frame)은 데이터를 주고받는 데 사용되는 데이터 단위 ()
struct EthernetHeader {

// u_char는 "unsigned char"의 줄임말로, 부호 없는 1바이트 정수 데이터를 표현하는 데이터 타입입니다. 
// 이 데이터 타입은 0부터 255까지의 값을 표현할 수 있습니다.
// u_char를 사용하는 이유는 주로 부호 없는 1바이트 정수 데이터를 표현해야 할 때 사용합니다. 
// 부호 없는 데이터 타입을 사용하면 값을 음수로 해석하지 않고, 0부터 양수 범위까지의 값을 표현할 수 있기 때문입니다. 
// 이러한 특징은 주로 바이너리 데이터를 다룰 때, 예를 들어 이미지 처리, 파일 입출력 등에서 유용하게 활용될 수 있습니다.
// 이러한 부호 없는 데이터 타입을 사용하는 이유는 MAC 주소가 음수가 될 수 없기 때문입니다.

    u_char dst_mac[6];  // 대상 MAC 주소 (6바이트)
    u_char src_mac[6];  // 소스 MAC 주소 (6바이트)
    u_short ether_type; // Ethernet 타입 (2바이트)
};




// print_mac_addr 함수는 MAC (Media Access Control) 주소를 사람이 읽기 쉬운 형식으로 출력하는 기능을 수행
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
        int res = pcap_next_ex(pcap, &header, &packet);        // 위 과정에서 각 정보들이 pcap , &header , &packet 에 저장됨 
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // packet 에 대해서 와이어 샤크로 잡았을때 헥사데이터가 보이게 된다.
        // 거기서 처음 6바이트 dst_mac 다음 6바이트는 src_mac 정보은
        

        
        // Ethernet 헤더를 추출하여 출력
        printf("------------------------------------------------------------------------------\n");
        struct EthernetHeader* eth_header = (struct EthernetHeader*)packet;    //packet에 저장된 데이터를 구조체로 받음
        printf("Ethernet Header\n");
        printf("Src MAC: ");
        print_mac_addr(eth_header->src_mac);
        printf("  Dst MAC: ");
        print_mac_addr(eth_header->dst_mac);
        printf("\n\n");
      
        // IP 헤더를 추출하여 출력
        // 코드에서 packet은 패킷 데이터가 저장된 포인터이고, sizeof(struct EthernetHeader)는 Ethernet 헤더의 크기를 나타냅니다. 
        // 이 코드는 Ethernet 헤더를 건너뛰고 IP 헤더의 시작 위치를 찾기 위해 packet 포인터에 Ethernet 헤더의 크기를 더하는 것


        // ip 구조체는 #include <netinet/ip.h> // for ip header 안에 있는 구조체를 가지고 와서 필요한 정보만 담는다.
        // 구조는 이러하다
        /*
            ip_hl: 헤더 길이 (Header Length)를 나타냅니다. 4바이트 단위로 표현되며, 최대 15를 나타냅니다.
            ip_v: IP 버전을 나타냅니다. IPv4의 경우 4로 설정됩니다.
            ip_tos: 서비스 유형 (Type of Service)을 나타냅니다.
            ip_len: IP 패킷의 전체 길이를 나타냅니다.
            ip_id: 패킷 식별자 (Identification)를 나타냅니다.
            ip_off: 패킷의 조각화 정보를 나타냅니다.
            ip_ttl: 패킷의 Time-to-Live (TTL) 값을 나타냅니다.
            ip_p: 상위 계층 프로토콜 (TCP, UDP 등)을 나타냅니다.
            ip_sum: IP 헤더의 체크섬 값을 나타냅니다.
            ip_src: 송신자(IP 출발지 주소)를 나타냅니다.
            ip_dst: 수신자(IP 도착지 주소)를 나타냅니다.
        */


        
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct EthernetHeader));
        printf("IP Header\n");
        // inet_ntoa() : 네트워크 주소를 사람이 읽기 쉬운 형식인 IPv4 주소 문자열로 변환하는 함수
        // <netinet/ip.h> 헤더 파일안에 있는 ip 라는 구조체에 담는다.
        printf("Src IP: %s  Dst IP: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
        printf("\n\n");


        // tcphdr 구조체는 #include <netinet/tcp.h> // for tcp header 안에 있는 구조체를 가지고 와서 필요한 정보만 담는다.
        // 구조는 이러하다
        /*
        th_sport: 송신자 포트 번호를 나타냅니다.
        th_dport: 수신자 포트 번호를 나타냅니다.
        th_seq: 시퀀스 번호를 나타냅니다.
        th_ack: 확인 응답 번호를 나타냅니다.
        th_off: 데이터 오프셋을 나타냅니다. 4바이트 단위로 표현되며, 최대 15를 나타냅니다.
        th_flags: 플래그 필드를 나타냅니다. FIN, SYN, RST, PUSH, ACK, URG 플래그 등이 포함됩니다.
        th_win: 윈도우 크기를 나타냅니다.
        th_sum: TCP 헤더의 체크섬 값을 나타냅니다.
        th_urp: 긴급 포인터를 나타냅니다.
        */
        
        
        // TCP 헤더를 추출하여 출력
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct EthernetHeader) + (ip_header->ip_hl << 2));
/*
궁금점..!
struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct EthernetHeader) + (ip_header->ip_hl << 2));

이것과

struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct EthernetHeader) + sizeof(struct ip_header) );

이거는 같아야 하지 않을까????

다르다 왜냐면 EthernetHeader 는 그 크기가 고정되어 있지만 ip 경우는 그 크기가 각기 다를 수 있다
때문에  ip_hl: 헤더 길이 (Header Length) 를 이용해서 크기를 가져와야 정확한 위치를 구할 수 있다.


*/
        
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
