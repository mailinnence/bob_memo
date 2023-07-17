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
		usage();                    // 사용법
		return false;
	}
	param->dev_ = argv[1];        // 사용자에게 받아온 인수를 대입시킨다.
	return true;
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
		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}

