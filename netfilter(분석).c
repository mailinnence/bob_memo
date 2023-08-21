#include <signal.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h> 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>



void handleCtrlC(int signal);

void handleCtrlC(int signal) {
    system("sudo iptables -F"); 
    exit(signal); 
}




void dump(unsigned char* buf, int size) {

	struct ip* ip_header = (struct ip*)buf;
	struct udphdr*  udp_header = (struct udphdr*)(buf  + (ip_header->ip_hl << 2));
	
	if (ip_header->ip_p == 17) 			{
		for (int i = 0; i < size; i++)	 {
			if (i != 0 && i % 16 == 0)
				printf("\n");
			printf("%02X ", buf[i]);
		}
		
		printf("\n\n");
		
		
		for (int i = 0; i < (ip_header -> ip_hl << 2) + 8 ; i++)	 {
			if (i != 0 && i % 16 == 0)
				printf("\n");
			printf("%02X ", buf[i]);
		}
	}
	printf("\n");
}








/* returns packet id */
/*

이 함수는 넷필터로부터 받은 데이터를 처리하고 패킷 정보를 출력하는 역할을 합니다. 
패킷의 정보(프로토콜, MAC 주소, 데이터 길이 등)을 출력하고, dump 함수를 호출하여 패킷 데이터를 출력합니다.

*/


static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	id = ntohl(ph->packet_id);
	
	return id;
}




/*

이 함수는 넷필터에서 캡처한 패킷에 대한 콜백 함수입니다. 
넷필터로부터 받은 데이터를 print_pkt 함수로 전달하여 패킷 정보를 출력하고, 
nfq_set_verdict 함수를 호출하여 패킷을 어떻게 처리할지 결정합니다. 
이 코드에서는 NF_ACCEPT로 설정하여 패킷을 허용합니다.

*/


static int cb(struct nfq_q_handle *qh , struct nfgenmsg *nfmsg , struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}







/*

프로그램의 메인 함수입니다. 주어진 인자로 호스트네임을 받아서 사용하고, Ctrl+C 시그널 핸들러를 등록하고 iptables 규칙을 설정합니다. 
그리고 넷필터 라이브러리를 초기화하고 캡처한 패킷을 처리하는 루프를 실행합니다.

이 코드는 네트워크 패킷을 캡처하고 출력하는 도구로 사용될 수 있습니다. 넷필터를 사용하여 캡처한 패킷의 정보를 출력하고 특정 패킷 처리 규칙을 적용할 수 있습니다. 
코드의 상세한 동작은 실행 환경과 입력에 따라 다르게 동작할 수 있습니다.

*/


int main(int argc, char **argv)
{	
	char* hostname;
	
	hostname = argv[1];
	
	
	
	signal(SIGINT, handleCtrlC);
	system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");
 	
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;

/*


struct nfq_handle, struct nfq_q_handle, 그리고 struct nfnl_handle은 libnetfilter_queue 라이브러리의 데이터 구조체입니다.

--------------------------------------
struct nfq_handle {
    int fd;
    int family;
    unsigned int queues_total;
    unsigned int queues_max;
    struct list_head queue_list;
    struct nfnl_handle *nfnlh;
    int subscriptions;
    // ... 기타 필드 ...
};
--------------------------------------


--------------------------------------
struct nfq_q_handle {
    struct nfq_handle *handle;
    struct nfnl_handle *nfnlh;
    u_int16_t id;
    nfq_callback *cb;
    void *data;
    struct list_head queue_list;
    struct nfq_q_handle *next;
    int fd;
    // ... 기타 필드 ...
};
--------------------------------------


--------------------------------------
struct nfnl_handle {
    int fd;
    int family;
    pid_t pid;
    __u32 seq;
    struct sockaddr_nl local;
    struct sockaddr_nl peer;
    // ... 기타 필드 ...
};
--------------------------------------


*/





	
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();


/*

nfq_open() 함수는 libnetfilter_queue 라이브러리에서 제공하는 함수 중 하나입니다. 
이 함수는 넷필터 라이브러리를 초기화하고 넷필터 핸들을 생성하는 역할을 합니다.
-------------------------------------------------------------------------------------------
"핸들"은 프로그래밍에서 특정 자원이나 객체에 대한 식별자나 참조를 나타내는 용어입니다. 
핸들은 해당 자원이나 객체에 접근하거나 조작하는 데 사용되며, 
대개 메모리 내의 특정 구조체나 값으로 표현됩니다
-------------------------------------------------------------------------------------------
h에 할당하는 작업을 수행합니다



*/

	
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}



/*

`nfq_unbind_pf`, `nfq_bind_pf`, `nfq_create_queue`, `nfq_set_mode`는 
모두 libnetfilter_queue 라이브러리의 함수로, 네트필터 관련 작업을 수행하기 위해 사용되는 함수입니다.

*/



	
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}


/*
1.`nfq_unbind_pf` ----------------------------------------------------------------------

   `int nfq_unbind_pf(struct nfq_handle *h, uint16_t pf);`
   
이 함수는 지정한 프로토콜 패밀리에 대한 넷필터 핸들을 언바인딩(unbinding)합니다. 
언바인딩은 해당 프로토콜 패밀리에 대한 넷필터 처리를 중지하고 관련 설정을 초기화하는 작업입니다. 
이 함수의 반환값은 성공 여부를 나타냅니다.
-----------------------------------------------------------------------------------------

*/

	

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}


	
/*
2. `nfq_bind_pf` ------------------------------------------------------------------------

   `int nfq_bind_pf(struct nfq_handle *h, uint16_t pf);`
   
이 함수는 지정한 프로토콜 패밀리에 대한 넷필터 핸들을 바인딩(binding)합니다. 
바인딩은 해당 프로토콜 패밀리에 대한 넷필터 처리를 시작하기 위한 설정을 수행하는 작업입니다. 
이 함수의 반환값은 성공 여부를 나타냅니다.
-----------------------------------------------------------------------------------------


*/


	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

/*
3. `nfq_create_queue` -------------------------------------------------------------------

   `struct nfq_q_handle *nfq_create_queue(struct nfq_handle *h, unsigned int num, nfq_callback *cb, void *data);`
   
이 함수는 지정한 넷필터 핸들과 큐 번호, 콜백 함수, 사용자 데이터를 기반으로 큐 핸들을 생성합니다. 
큐 핸들은 패킷을 캡처하고 처리하기 위한 설정을 가지며, 캡처한 패킷을 해당 콜백 함수로 보내서 처리합니다. 
반환값은 생성된 큐 핸들입니다.
-----------------------------------------------------------------------------------------
*/


	
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}


/*
4. `nfq_set_mode` -----------------------------------------------------------------------

   `int nfq_set_mode(struct nfq_q_handle *qh, u_int8_t mode, u_int32_t range);`
   
이 함수는 큐 핸들의 동작 모드와 범위를 설정합니다. 동작 모드는 패킷 처리 모드를 설정하며, 
범위는 캡처할 패킷의 최대 길이를 설정합니다. 이 함수의 반환값은 성공 여부를 나타냅니다.
-----------------------------------------------------------------------------------------
*/


/*
이 함수들은 libnetfilter_queue 라이브러리의 일부로, 네트워크 패킷을 캡처하고 처리하기 위한 설정 및 동작을 수행하는 데 사용됩니다. 
코드에서 각 함수가 호출되면서 넷필터의 동작을 설정하고 초기화하는 역할을 합니다.
*/

	
	fd = nfq_fd(h);


/*
fd = nfq_fd(h);는 libnetfilter_queue 라이브러리에서 제공하는 함수 중 하나입니다. 
이 함수는 넷필터 핸들에 연결된 파일 디스크립터를 반환합니다. 
파일 디스크립터는 넷필터 핸들과 관련된 작업을 수행할 때 사용됩니다.

일반적으로 이 함수는 recv 함수와 함께 사용되어 넷필터로부터 패킷을 읽어오는 작업에 활용됩니다. 
넷필터로부터 수신된 패킷은 해당 파일 디스크립터를 통해 읽어올 수 있습니다.

따라서 fd = nfq_fd(h);는 넷필터 핸들 h에 연결된 파일 디스크립터를 변수 fd에 할당하는 역할을 합니다. 
이렇게 얻은 파일 디스크립터를 이용하여 넷필터로부터 패킷을 읽어올 수 있습니다.
*/


	// 넷필터를 사용하여 캡처한 패킷을 읽어오고 처리하는 루프
	for (;;) {	
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
	/*
		recv 함수:
		ssize_t recv(int sockfd, void *buf, size_t len, int flags);
		
		이 함수는 파일 디스크립터 fd에서 데이터를 읽어오는 역할을 합니다. 
		buf에 읽은 데이터를 저장하며, len은 읽을 최대 바이트 수를 나타냅니다. 
		flags는 함수 호출 동작을 제어하는 플래그입니다. 
		함수는 읽은 바이트 수를 반환하거나 오류가 발생하면 -1을 반환합니다.
 	*/
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);

	/*
		nfq_handle_packet 함수:
		int nfq_handle_packet(struct nfq_handle *h, char *buf, int len);
		
		이 함수는 캡처한 패킷을 처리하는 역할을 합니다. 
		넷필터 핸들 h와 패킷 데이터 buf를 매개변수로 받으며, 
		len은 패킷의 길이를 나타냅니다. 
		이 함수는 캡처한 패킷을 적절한 처리를 위해 큐 핸들의 콜백 함수로 보내주는 역할을 합니다.
	*/
			
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}
	/*
	 	루프내
		1.recv 함수를 통해 패킷을 읽어옵니다.
		2.rv에는 읽은 바이트 수가 저장됩니다.
		3.읽은 패킷 데이터를 nfq_handle_packet 함수에 전달하여 패킷을 처리합니다.
		4.ENOBUFS 오류가 발생하면 패킷을 읽을 수 없는 상황으로, 패킷을 잃어버린 것을 나타냅니다. 이 경우 계속해서 다음 패킷을 읽어오도록 합니다.
		5.rv가 음수이고 오류가 ENOBUFS가 아닌 다른 오류인 경우, perror 함수를 사용하여 오류 메시지를 출력하고 루프를 종료합니다.
	*/
	
	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

	/*
		nfq_destroy_queue 함수는 libnetfilter_queue 라이브러리에서 제공되며, 
		생성된 큐 핸들을 파괴하고 관련 리소스를 해제하는 역할을 수행합니다. 
		이 함수를 사용하여 큐 핸들을 사용한 후에는 해당 핸들을 메모리에서 
		해제하여 누수(leak)를 방지하고 프로그램 종료 시에 자원을 올바르게 정리할 수 있습니다.
		
		void nfq_destroy_queue(struct nfq_q_handle *qh);
		
		qh: 파괴하고자 하는 큐 핸들을 나타내는 구조체 포인터입니다.
		이 함수를 호출하면 큐 핸들이 파괴되며, 큐에 연관된 리소스 및 설정들이 해제됩니다. 
		
		이후에는 해당 핸들을 더 이상 사용해서는 안됩니다.
		이 함수를 사용하여 네트필터 큐 핸들을 정리하고 해제하는 것은 메모리 누수와 같은 문제를 방지하는데 중요한 역할을 합니다.
	*/
	

#ifdef INSANE
	
	/*
	이 부분은 컴파일러 지시문으로, INSANE이라는 매크로가 정의되어 있을 때에만 해당 블록의 코드가 컴파일되도록 설정합니다. 
	매크로가 정의되어 있지 않으면 이 부분의 코드는 무시됩니다.
	
	
	위 코드에서는 INSANE 매크로가 정의된 경우에만, 
	nfq_unbind_pf 함수를 호출하여 프로토콜 패밀리 AF_INET에 대한 넷필터 핸들을 언바인딩합니다. 
	이는 프로그램 종료 시 넷필터와의 연결을 정리하는 작업입니다.
	*/

	
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	
	/*
		nfq_close:
		void nfq_close(struct nfq_handle *h);
		
		이 함수는 넷필터 핸들을 닫아서 관련 리소스를 해제하는 역할을 합니다. 
  		이 함수를 호출하면 넷필터 라이브러리와 관련된 메모리와 자원을 올바르게 정리합니다.
	 */

	
	exit(0);  // 이 함수는 프로그램을 종료하는 역할을 합니다. 인자로 전달되는 값은 종료 상태 코드를 나타냅니다. 0은 정상 종료를 나타냅니다.
	
	
}
