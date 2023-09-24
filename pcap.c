#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

// Ethernet 헤더 구조체 정의
struct EthernetHeader {
	u_char  ether_dhost[6];    // Destination host 주소
	u_char  ether_shost[6];    // Source host 주소
	u_short ether_type;        // IP? ARP? RARP? etc
};

// IP 헤더 구조체 정의
struct IPHeader {
  unsigned char      iph_ihl:4, // IP 헤더 길이
                     iph_ver:4; // IP 버전
  unsigned char      iph_tos; // Type of service (서비스 유형)
  unsigned short int iph_len; // IP Packet 길이 (data + header)
  unsigned short int iph_ident; // Identification (식별자)
  unsigned short int iph_flag:3, // Fragmentation flags
                     iph_offset:13; // Flags offset
  unsigned char      iph_ttl; // Time to Live
  unsigned char      iph_protocol; // Protocol type
  unsigned short int iph_chksum; // IP 데이터그램 checksum
  struct  in_addr    iph_sourceip; // Source IP 주소
  struct  in_addr    iph_destip;   // Destination IP 주소
};

// TCP 헤더 구조체 정의
struct TCPHeader {
    u_short tcp_sport;               // Source Port
    u_short tcp_dport;               // Destination Port
    u_int   tcp_seq;                 // 시퀀스 번호
    u_int   tcp_ack;                 // 확인 번호
    u_char  tcp_offx2;               // data offset, rsvd
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 // window
    u_short tcp_sum;                 // checksum
    u_short tcp_urp;                 // urgent pointer
};

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct EthernetHeader *eth_header;
    struct IPHeader *ip_header;
    struct TCPHeader *tcp_header;

    // Ethernet 헤더 정보 추출
    eth_header = (struct EthernetHeader *)packet;

    // IP 헤더의 시작 위치 계산
    int ether_header_size = sizeof(struct ether_header);
    ip_header = (struct IPHeader *)(packet + ether_header_size);

    // TCP 헤더의 시작 위치 계산
    int ip_header_size = (ip_header->iph_ihl & 0x0F) * 4;
    tcp_header = (struct TCPHeader *)((char *)ip_header + ip_header_size);

    // 패킷 정보 출력
    printf("\n=================================\n");
    printf("TCP protocol로 통신 중인 디바이스\n");
    printf("---------------------------------\n");
    printf("Src MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_shost));
    printf("Dst MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_dhost));
    printf("Src IP: %s\n", inet_ntoa(ip_header->iph_sourceip));
    printf("Dst IP: %s\n", inet_ntoa(ip_header->iph_destip));
    printf("Src Port: %d\n", ntohs(tcp_header->tcp_sport));
    printf("Dst Port: %d\n", ntohs(tcp_header->tcp_dport));
    printf("=================================\n");
}

int main() {
    pcap_t *handle;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 네트워크 디바이스 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치를 열 수 없음 %s: %s\n", dev, errbuf);
        return 1;
    }

    // 패킷 캡처 및 처리
    pcap_loop(handle, -1, packet_handler, NULL);

    // 핸들 닫기
    pcap_close(handle);

    return 0;
}