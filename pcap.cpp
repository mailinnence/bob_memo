#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

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



bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {              // if (argc != 2) {: 만약 실행 인수의 개수(argc)가 2가 아니면 실행합니다.
		usage();              // 사용법
		return false;
	}
	param->dev_ = argv[1];        // 사용자에게 받아온 인수를 대입시킨다.
	return true;
}

/*
디테일한 해석
argv[1]은 사용자가 입력한 첫 번째 인수를 나타냅니다. 
C 언어의 배열 인덱스는 0부터 시작하므로, 
argv[0]은 프로그램의 이름(실행 파일 이름)을 가리키고, argv[1]은 첫 번째 인수를 가리킵니다.

따라서, 예를 들어 sudo ./pcap-test와 같이 실행한 경우 argc는 1이 되며, argc != 2 조건이 참이 되어 인수가 부족하다는 경고 메시지를 출력하게 됩니다. 
그리고 sudo ./pcap-test ens33와 같이 실행한 경우 argc는 2이며, argv[1]은 "ens33"라는 문자열을 가리키게 됩니다. 이는 사용자가 입력한 네트워크 인터페이스를 나타내게 됩니다.

정리하자면 프로그램의 이름 + 인터페이스 = 2 이기 떄문에 받아온 인자의 갯수가 2가 아니라면  if (argc != 2) {  .... 
실행하지말고 사용법을 보여주는 usage 함수를 실행하라는 것 입니다.
*/




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


/*
param.dev_: 캡처할 네트워크 인터페이스의 이름을 나타내는 문자열입니다. 이는 사용자로부터 입력받은 인터페이스 이름입니다.
BUFSIZ: 패킷 캡처를 위한 버퍼의 크기입니다. BUFSIZ는 libpcap에서 미리 정의된 상수로, 보통 8192바이트로 설정됩니다. 
        이 버퍼는 캡처한 패킷 데이터를 임시로 저장하는 용도로 사용됩니다.
1: 캡처된 패킷을 즉시 처리하기 위한 옵션입니다. 1로 설정하면 패킷이 도착할 때마다 처리가 진행됩니다.
1000: 패킷을 캡처하기 위한 타임아웃 값입니다. 이 값은 밀리초 단위로 설정됩니다. 1000으로 설정하면 1초마다 타임아웃이 발생하여 패킷 캡처 작업이 수행됩니다.
errbuf: 오류 메시지를 저장하기 위한 버퍼입니다. 함수가 실패한 경우 오류 메시지가 errbuf에 저장됩니다.


*/

	
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}


	// pcap_open_live() 함수가 실패한 경우를 처리하는 부분
	// pcap_open_live() 함수는 네트워크 인터페이스에서 패킷 캡처 세션을 열고, 세션 핸들인 pcap_t를 반환합니다. 
	// 그러나 pcap_open_live() 함수가 실패하면 NULL을 반환하게 됩니다.
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}

