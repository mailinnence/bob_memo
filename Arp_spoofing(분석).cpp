// mac.h ---------------------------------------------------------------------------------------

#pragma once

#include <cstdint>

/*
        <cstdint> 라이브러리는 C++11부터 도입된 헤더 파일로, 정수형 데이터 타입들에 대한 고정 크기 정의를 제공합니다. 
        이는 다양한 플랫폼에서 정수형 데이터 타입의 크기를 일관성 있게 처리하기 위해 사용됩니다.
        C++에서 정수형 데이터 타입의 크기는 시스템에 따라 다를 수 있으므로, 
        이 헤더를 사용하여 특정 크기의 정수형을 명시적으로 지정할 수 있습니다.
        <cstdint>에서 제공하는 주요 정수형 타입은 다음과 같습니다:
        
        std::int8_t, std::int16_t, std::int32_t, std::int64_t: 부호 있는 정수형 데이터 타입으로, 8비트, 16비트, 32비트, 64비트 크기를 가집니다.
        std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t: 부호 없는 정수형 데이터 타입으로, 8비트, 16비트, 32비트, 64비트 크기를 가집니다.
        
        ex)
        
        #include <cstdint>
        
        std::int32_t myInt32 = 42;
        std::uint16_t myUInt16 = 65535;
*/



#include <cstring>
/*
	<cstring> 라이브러리는 C 스타일 문자열 (null로 끝나는 문자 배열)을 다루는데 사용됩니다. 
	C++에서 문자열은 std::string 클래스로 표현할 수도 있지만, 
	기존 C 코드와 상호작용이 필요한 경우 C 스타일 문자열을 사용해야 할 때가 있습니다.
	<cstring>에서 제공하는 일부 주요 함수들은 다음과 같습니다:
	
	strcpy: 문자열을 복사합니다.
	strcat: 문자열을 이어붙입니다.
	strlen: 문자열의 길이를 계산합니다.
	strcmp: 두 문자열을 비교합니다.
	예시:
	
	cpp
	Copy code
	#include <cstring>
	
	char source[] = "Hello";
	char destination[20];
	strcpy(destination, source); // "Hello"를 destination으로 복사합니다.


*/



#include <string>
/*
	<string> 라이브러리는 C++에서 문자열을 처리하는 데 사용되는 헤더 파일입니다.  
	C++에서 제공하는 std::string 클래스는 C 스타일 문자열보다 더 편리하고 유연한 문자열 처리 방법을 제공합니다. 
	std::string은 문자열의 길이를 자동으로 추적하고, 메모리 관리를 자동으로 
	처리하여 안전하고 편리한 문자열 조작을 가능하게 합니다.
	<string>에서 std::string 클래스가 제공하는 일부 주요 멤버 함수들은 다음과 같습니다:
	
	append: 문자열을 뒤에 이어붙입니다.
	length 또는 size: 문자열의 길이를 반환합니다.
	substr: 문자열의 일부분을 추출합니다.
	예시:
	
	cpp
	Copy code
	#include <string>
	
	std::string myString = "Hello, C++!";
	myString.append(" Welcome"); // "Welcome"을 문자열 끝에 추가합니다.
*/

// ----------------------------------------------------------------------------
// Mac
// ----------------------------------------------------------------------------
struct Mac final {
	static constexpr int SIZE = 6;

	// constructor
	Mac() {}
	Mac(const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); }
	Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
	Mac(const std::string& r);

	// assign operator
	Mac& operator = (const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); return *this; }

	// casting operator
	explicit operator uint8_t*() const { return const_cast<uint8_t*>(mac_); }
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }
	bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) != 0; }
	bool operator < (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) < 0; }
	bool operator > (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) > 0; }
	bool operator <= (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) <= 0; }
	bool operator >= (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) >= 0; }
	bool operator == (const uint8_t* r) const { return memcmp(mac_, r, SIZE) == 0; }

	void clear() {
		*this = nullMac();
	}

	bool isNull() const {
		return *this == nullMac();
	}

	bool isBroadcast() const { // FF:FF:FF:FF:FF:FF
		return *this == broadcastMac();
	}

	bool isMulticast() const { // 01:00:5E:0*
		return mac_[0] == 0x01 && mac_[1] == 0x00 && mac_[2] == 0x5E && (mac_[3] & 0x80) == 0x00;
	}

	static Mac randomMac();
	static Mac& nullMac();
	static Mac& broadcastMac();

protected:
	uint8_t mac_[SIZE];
};

namespace std {
	template<>
	struct hash<Mac> {
		size_t operator() (const Mac& r) const {
			return std::_Hash_impl::hash(&r, Mac::SIZE);
		}
	};
}

// ------------------------------------------------------------------------------------------------








// ip.h --------------------------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <string>

struct Ip final {
	static const int SIZE = 4;

	// constructor
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	// casting operator
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }

	bool isLocalHost() const { // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const { // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}

protected:
	uint32_t ip_;
};


// ------------------------------------------------------------------------------------------------





// ethhdr.h ---------------------------------------------------------------------------------------
#pragma once
#include <arpa/inet.h>
#include "mac.h"
#pragma pack(push, 1)
struct EthHdr final {
	Mac dmac_;
	Mac smac_;
	uint16_t type_;
	Mac dmac() { return dmac_; }
	Mac smac() { return smac_; }
	uint16_t type() { return ntohs(type_); }
	// Type(type_)
	enum: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};
typedef EthHdr *PEthHdr;
#pragma pack(pop)


// -------------------------------------------------------------------------------------------------








// arphdr.h ---------------------------------------------------------------------------------------
#pragma once
#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"
#pragma pack(push, 1)
struct ArpHdr final {
	uint16_t hrd_;
	uint16_t pro_;
	uint8_t hln_;
	uint8_t pln_;
	uint16_t op_;
	Mac smac_;
	Ip sip_;
	Mac tmac_;
	Ip tip_;
	uint16_t hrd() { return ntohs(hrd_); }
	uint16_t pro() { return ntohs(pro_); }
	uint8_t hln() { return hln_;}
	uint8_t pln() { return pln_;}
	uint16_t op() { return ntohs(op_); }
	Mac smac() { return smac_; }
	Ip sip() { return ntohl(sip_); }
	Mac tmac() { return tmac_; }
	Ip tip() { return ntohl(tip_); }
	// HardwareType(hrd_)
	enum: uint16_t {
		NETROM = 0, // from KA9Q: NET/ROM pseudo
		ETHER = 1, // Ethernet 10Mbps
		EETHER = 2, // Experimental Ethernet
		AX25 = 3, // AX.25 Level 2
		PRONET = 4, // PROnet token ring
		CHAOS = 5, // Chaosnet
		IEEE802 = 6, // IEEE 802.2 Ethernet/TR/TB
		ARCNET = 7, // ARCnet
		APPLETLK = 8, // APPLEtalk
		LANSTAR = 9, // Lanstar
		DLCI = 15, // Frame Relay DLCI
		ATM = 19, // ATM
		METRICOM = 23, // Metricom STRIP (new IANA id)
		IPSEC = 31 // IPsec tunnel
	};
	// Operation(op_)
	enum: uint16_t {
		Request = 1, // req to resolve address
		Reply = 2, // resp to previous request
		RevRequest = 3, // req protocol address given hardware
		RevReply = 4, // resp giving protocol address
		InvRequest = 8, // req to identify peer
		InvReply = 9 // resp identifying peer
	};
};
typedef ArpHdr *PArpHdr;
#pragma pack(pop)








// ------------------------------------------------------------------------------------------------














// main.cpp ---------------------------------------------------------------------------------------

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}

// ------------------------------------------------------------------------------------------------
