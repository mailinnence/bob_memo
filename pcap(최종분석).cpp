#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h> 

void usage() {
    printf("syntax: pcap-test <interface>\n");  // <interface>는 사용자가 지정해야 할 네트워크 인터페이스를 나타내며
    printf("sample: pcap-test wlan0\n");        // 그 예시르 보여준다
}


typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};
// .Param 을 가지고 와서 .dev_ = NULL 로 초기화





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







// print_ip_address 함수는 주어진 struct in_addr 형식의 IP 주소를 사람이 읽을 수 있는 형태로 출력하는 함수입니다. 
// struct in_addr는 <netinet/ip.h> 헤더에 정의된 구조체로, 네트워크에서 사용되는 32비트 IP 주소를 표현하는 데 사용
void print_ip_address(const struct in_addr* ip_addr) {
    const u_char* ip_bytes = (const u_char*)ip_addr;
    printf("%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
}





bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}




// 주어진 바이트 배열(u_char 형식으로 표현된 데이터)을 16진수로 출력하는 함수
void print_hex(const u_char* packet, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n\n");
}

void print_ip_hex(const struct in_addr* ip_addr) {
    const u_char* ip_bytes = (const u_char*)ip_addr;
    printf("%02x:%02x:%02x:%02x",
           ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
}

void print_tcp_hex(const struct in_addr* tcp_addr) {
    const u_char* tcp_bytes = (const u_char*)tcp_addr;
    printf("%02x:%02x:",
           tcp_bytes[0], tcp_bytes[1]);
}



/* -----------------------------------------------------------------------------
디테일한 해석
argv[1]은 사용자가 입력한 첫 번째 인수를 나타냅니다. 
C 언어의 배열 인덱스는 0부터 시작하므로, 
argv[0]은 프로그램의 이름(실행 파일 이름)을 가리키고, argv[1]은 첫 번째 인수를 가리킵니다.

따라서, 예를 들어 sudo ./pcap-test와 같이 실행한 경우 argc는 1이 되며, argc != 2 조건이 참이 되어 인수가 부족하다는 경고 메시지를 출력하게 됩니다. 
그리고 sudo ./pcap-test ens33와 같이 실행한 경우 argc는 2이며, argv[1]은 "ens33"라는 문자열을 가리키게 됩니다. 이는 사용자가 입력한 네트워크 인터페이스를 나타내게 됩니다.

정리하자면 프로그램의 이름 + 인터페이스 = 2 이기 떄문에 받아온 인자의 갯수가 2가 아니라면  if (argc != 2) {  .... 
실행하지말고 사용법을 보여주는 usage 함수를 실행하라는 것 입니다.
*/ -----------------------------------------------------------------------------




int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))		// 인자 확인 함수 실행
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];		// libpcap의 헤더 파일(<pcap.h>)에서 가져온 define 된 변수로 PCAP_ERRBUF_SIZE는 256으로 정의됩니다.
						// errbuf 배열은 256바이트 크기로 선언되어 오류 메시지를 저장하는 역할을 합니다



	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	// pcap_t는 libpcap에서 정의된 네트워크 패킷 캡처 세션 핸들을 나타내는 자료형
	// pcap_open_live() 함수는 libpcap 라이브러리에서 제공되는 함수로, 네트워크 인터페이스에서 실시간으로 패킷을 캡처하기 위한 세션을 엽니다
	// 성공적으로 패킷 캡처 세션을 열면 해당 세션에 대한 핸들을 반환하며, 
	// 이를 pcap_t* 타입의 포인터인 pcap 변수에 저장합니다. 이 핸들은 이후 패킷 캡처 세션을 조작하거나 패킷을 가져오기 위해 사용됩니다.


/* -----------------------------------------------------------------------------
param.dev_: 캡처할 네트워크 인터페이스의 이름을 나타내는 문자열입니다. 이는 사용자로부터 입력받은 인터페이스 이름입니다.
BUFSIZ: 패킷 캡처를 위한 버퍼의 크기입니다. BUFSIZ는 libpcap에서 미리 정의된 상수로, 보통 8192바이트로 설정됩니다. 
        이 버퍼는 캡처한 패킷 데이터를 임시로 저장하는 용도로 사용됩니다.
1: 캡처된 패킷을 즉시 처리하기 위한 옵션입니다. 1로 설정하면 패킷이 도착할 때마다 처리가 진행됩니다.
1000: 패킷을 캡처하기 위한 타임아웃 값입니다. 이 값은 밀리초 단위로 설정됩니다. 1000으로 설정하면 1초마다 타임아웃이 발생하여 패킷 캡처 작업이 수행됩니다.
errbuf: 오류 메시지를 저장하기 위한 버퍼입니다. 함수가 실패한 경우 오류 메시지가 errbuf에 저장됩니다.


*/ -----------------------------------------------------------------------------


	
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
	// pcap_open_live() 함수가 실패한 경우를 처리하는 부분
	// pcap_open_live() 함수는 네트워크 인터페이스에서 패킷 캡처 세션을 열고, 세션 핸들인 pcap_t를 반환합니다. 
	// 그러나 pcap_open_live() 함수가 실패하면 NULL을 반환하게 됩니다.
	
    while (true) {
        struct pcap_pkthdr* header;

		// struct pcap_pkthdr 구조체는 주로 libpcap 라이브러리에서 정의되어 있습니다. 
		// 이 라이브러리는 네트워크 패킷 캡처를 위한 기능을 제공하고, 네트워크 트래픽 분석과 패킷 처리를 위해 사용됩니다.
		
/* -----------------------------------------------------------------------------
struct pcap_pkthdr {
	struct timeval ts;  // 캡처된 패킷의 타임스탬프 (시간 정보)
	bpf_u_int32 caplen; // 캡처된 패킷의 길이 (caplen <= len)
	bpf_u_int32 len;    // 실제 패킷의 길이 (len은 패킷의 전체 길이)
	};		
*/ -----------------------------------------------------------------------------
		
	    
        const u_char* packet;
		// u_char는 C 언어에서 사용되는 데이터 타입 중 하나로, "unsigned char"를 나타내는 줄임말입니다. 
		// 이는 부호 없는 8비트 정수를 나타내는 자료형으로, 값의 범위는 0부터 255까지입니다.

		// u_char 타입은 주로 바이트 단위의 데이터를 다루는 경우에 사용됩니다. 네트워크 패킷 처리, 이미지 처리, 이진 데이터 등의 다양한 상황에서 자주 활용됩니다. 
		// libpcap 라이브러리에서도 네트워크 패킷을 다루는데 사용되는 데이터의 타입으로 u_char가 자주 사용됩니다
		
		// char 쓰면 안되는 이유

/* -----------------------------------------------------------------------------
1.데이터 손실:
네트워크 패킷은 0부터 255까지의 값으로 이루어지는 이진 데이터입니다. 
패킷에 포함된 바이너리 데이터를 char 타입으로 처리하면, char 타입은 -128부터 127까지의 범위를 
가지므로 128부터 255 사이의 값은 정수로 표현될 때 음수로 간주됩니다. 
이로 인해 데이터 손실이 발생할 수 있습니다.

2.비교와 검사:
패킷 데이터의 일부 필드를 비교하거나 특정 값과 검사해야 할 때, u_char (부호 없는 정수)로 처리하는 것이 더 간편합니다. 
비트 비교 및 AND/OR 비트 연산과 같은 비트 수준의 작업에 u_char 타입을 사용하면 오류 없이 수행할 수 있습니다.
		
3.일관성:
패킷 처리 시에는 일반적으로 u_char 타입을 사용하는 것이 
네트워크에서 주고 받는 데이터 형식과 일관성을 유지하는 데 도움이 됩니다. 
네트워크 데이터는 주로 부호 없는 정수 형태로 인코딩되고 전송되는 경우가 많으므로, 
이와 일치하는 데이터 타입을 사용하면 더 적합하고 이해하기 쉬운 코드를 작성할 수 있습니다.
*/ -----------------------------------------------------------------------------
		
	    
        int res = pcap_next_ex(pcap, &header, &packet);          // 위 과정에서 각 정보들이 pcap , &header , &packet 에 저장됨

/*

pcap_next_ex 함수는 libpcap 라이브러리의 주요 함수 중 하나로, 다음 패킷을 캡처하는 역할을 합니다.
이 함수는 네트워크 인터페이스로부터 다음 패킷을 읽어와서 메모리에 저장하고, 
해당 패킷에 대한 정보를 header와 packet 포인터를 통해 제공합니다.
함수의 반환값은 캡처한 패킷의 성공 여부를 나타내며, 상세한 정보는 res 변수에 저장됩니다.


int pcap_next_ex(
    pcap_t *p,            	      // pcap 핸들
    struct pcap_pkthdr **pkt_header,  // 캡처한 패킷의 헤더 정보를 저장하기 위한 포인터 변수
    const u_char **pkt_data	      // 캡처한 패킷의 데이터를 저장하기 위한 포인터 변수
);


>>

int res = pcap_next_ex(
			pcap, 		// 실시간으로 패킷을 캡처하기 위한 세션
   			&header, 	// 캡처한 패킷의 헤더 정보
							struct pcap_pkthdr {
								struct timeval ts;  // 캡처된 패킷의 타임스탬프 (시간 정보)
								bpf_u_int32 caplen; // 캡처된 패킷의 길이 (caplen <= len)
								bpf_u_int32 len;    // 실제 패킷의 길이 (len은 패킷의 전체 길이)
								};		
      			&packet		// 캡처한 패킷의 데이터를 저장하기 위한 포인터 변수
	 );
*/

	    
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			// pcap_geterr(pcap) 함수를 사용하여 pcap 핸들에 저장된 오류 메시지를 가져옵니다.
			// 오류가 발생한 경우: res 값은 PCAP_ERROR 또는 PCAP_ERROR_BREAK와 같은 오류 코드입니다. 
			// 이 경우 pcap_geterr(pcap) 함수를 사용하여 pcap 핸들에 저장된 오류 메시지를 가져오고, 
			// 오류 내용과 함께 오류 메시지를 출력
			// %d와 %s는 printf 함수에서 사용하는 형식 지정자로, 순서대로 res와 pcap_geterr(pcap)의 값을 출력합니다.		
            break;
        }


        // packet 에 대해서 와이어 샤크로 잡았을때 헥사데이터가 보이게 된다.
        // 거기서 처음 6바이트 dst_mac 다음 6바이트는 src_mac 정보은
        


      
        // print_hex(packet, header->caplen);

        printf("------------------------------------------------------------------------------\n");
        // Ethernet 헤더를 추출하여 출력
        struct EthernetHeader* eth_header = (struct EthernetHeader*)packet;
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
      
        // ip 헤더를 추출하여 출력
      	struct ip* ip_header = (struct ip*)(packet + sizeof(struct EthernetHeader));
      	printf("IP Header\n"); 
      	printf("Src IP: ");
      	print_ip_address(&ip_header->ip_src);
      	printf("  Dst IP: ");
      	print_ip_address(&ip_header->ip_dst);
      	printf("\n\n");

 
        // ip 헤더 헥스값값 출력
        // printf("IP Header\n");
        // printf("Src IP: ");
        // print_ip_hex(&ip_header->ip_src);
        // printf("  Dst IP: ");
        // print_ip_hex(&ip_header->ip_dst);
        // printf("\n\n");
    	// printf("\n\n");





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
	    
	struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct EthernetHeader) + (ip_header->ip_hl << 2));
	/*

	궁금점..!
	struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct EthernetHeader) + (ip_header->ip_hl << 2));
	
	이것과
	
	struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct EthernetHeader) + sizeof(struct ip_header) );
	
	이거는 같아야 하지 않을까????
	
	다르다 왜냐면 EthernetHeader 는 그 크기가 고정되어 있지만 ip 경우는 그 크기가 각기 다를 수 있다
	때문에  ip_hl: 헤더 길이 (Header Length) 를 이용해서 크기를 가져와야 정확한 위치를 구할 수 있다.
	sizeof() 와 더하야 하기 때문에 <<2 작업이 필요하다

	gpt 가라사대 --------------------------------------------------------------------------------------------------------------
	<< 2 연산을 사용하여 IP 헤더의 워드 단위를 바이트 단위로 변환하는 이유는 TCP 헤더와 Payload의 위치를 계산하기 위함입니다. 
 	TCP 헤더는 IP 헤더 이후에 위치하며, IP 헤더의 길이를 바이트 단위로 계산하기 위해 << 2 연산을 사용하여 올바른 위치를 찾아냅니다. 
  	따라서 packet + sizeof(struct EthernetHeader) + (ip_header->ip_hl << 2)는 TCP 헤더의 시작 위치를 가리키게 됩니다.
	---------------------------------------------------------------------------------------------------------------------------
	*/
	
	printf("TCP Header\n");
        printf("Src Port: %u  Dst Port: %u", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
        printf("\n\n");



	    

        // Payload(Data)의 hexadecimal value 출력
	// 네트워크 패킷에서 Payload 또는 Data 부분의 16진수 값을 출력하는 부분을 담당합니다. 
	// Payload는 네트워크 패킷에서 유저 데이터가 담겨 있는 부분을 의미합니다. 
	// 네트워크 패킷은 헤더(Header)와 Payload(데이터)로 구성되어 있으며, 
	// 헤더는 네트워크 장비가 패킷을 전달하고 처리하는 데 필요한 정보를 담고 있습니다. 
	// Payload는 실제 데이터를 포함하고 있으며, 예를 들어 웹 페이지의 HTML 내용, 파일의 내용 등이 Payload로 전송됩니다.

	    
        const u_char* payload = packet + sizeof(struct EthernetHeader) + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);

	// 네트워크 패킷에서 Payload 또는 Data 부분의 16진수 값을 출력하는 부분을 담당합니다. 
	// Payload는 네트워크 패킷에서 유저 데이터가 담겨 있는 부분을 의미합니다. 
	// 네트워크 패킷은 헤더(Header)와 Payload(데이터)로 구성되어 있으며, 
	// 헤더는 네트워크 장비가 패킷을 전달하고 처리하는 데 필요한 정보를 담고 있습니다. 
	// Payload는 실제 데이터를 포함하고 있으며, 예를 들어 웹 페이지의 HTML 내용, 파일의 내용 등이 Payload로 전송됩니다.

	// ip 에 포함되어 있는 Payload 정보를 추출하려면 tpc 위치 시작 위치에서 빼가는 방식으로 접근한다.
	// 실제 크기로 뺼수 있도록 네트워크 바이트 순서에서 호스트 바이트 순서로 16비트(short) 정수 값을 변환하는 함수 ntohs을 이용한다
	/*
	    ip_hl: 헤더 길이 (Header Length)를 나타냅니다. 4바이트 단위로 표현되며, 최대 15를 나타냅니다.
            ip_off: 패킷의 조각화 정보를 나타냅니다.
        
	    을 빼면 payload 값이 나오게 되고 그 중 10바이트 까지만 출력한다.
	*/
	    
	    
        int payload_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl << 2) - (tcp_header->th_off << 2);
        printf("Payload(Data) (Hexadecimal Value):\n");
        for (int i = 0; i < payload_len && i < 10; i++) {
            printf("%02x ", payload[i]);
        }
	
        printf("\n------------------------------------------------------------------------------\n\n");
    }

    pcap_close(pcap);
}
