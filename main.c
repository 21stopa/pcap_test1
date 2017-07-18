#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define SIZE_ETHER_HEADER 14
#define MAXIMUM_CAPTURE_COUNT 10
typedef struct ether_header{
    u_char dst_mac[ETHER_ADDR_LEN];
    u_char src_mac[ETHER_ADDR_LEN];
    u_int16_t ether_type;
}ETHER_HEADER;

typedef struct ip_header{
    u_char version_Hlength;
    u_char ToS;
    u_int16_t total_Length;
    u_int16_t id;
    u_int16_t frag_Offset;
    u_char ttl;
    u_char protocol;
    u_int16_t checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
}IP_HEADER;

typedef struct tcp_header{
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int32_t seq;
    u_int32_t ack;
    u_char data_Offset;
    u_char flags;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urgp;
}TCP_HEADER;

ETHER_HEADER ether_Container;
IP_HEADER ip_Container;
TCP_HEADER tcp_Container;
u_char* data;
void show_data(const struct pcap_pkthdr *header, const u_char *packet)
{
    int size_ipheader = 0;
    int size_tcpheader = 0;
    ether_Container = *(ETHER_HEADER*)packet;
    if(ntohs(ether_Container.ether_type) != 0x0800) return;

    ip_Container = *(IP_HEADER*)(packet+SIZE_ETHER_HEADER);
    size_ipheader = (ip_Container.version_Hlength & 0x0f) * 4;

    if((ip_Container.protocol != IPPROTO_TCP)) return;

    tcp_Container = *(TCP_HEADER*)(packet+SIZE_ETHER_HEADER+size_ipheader);

    size_tcpheader = ((tcp_Container.data_Offset >> 4) & 0x0f) * 4;
    if(!((ntohs(tcp_Container.dst_port) == 0x0050) || (ntohs(tcp_Container.src_port) == 0x0050))) return;

    printf("eth.smac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ether_Container.src_mac[0],ether_Container.src_mac[1],ether_Container.src_mac[2],ether_Container.src_mac[3],ether_Container.src_mac[4],ether_Container.src_mac[5]);
    printf("eth.dmac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ether_Container.dst_mac[0],ether_Container.dst_mac[1],ether_Container.dst_mac[2],ether_Container.dst_mac[3],ether_Container.dst_mac[4],ether_Container.dst_mac[5]);

    printf("ip.sip: %s\n", inet_ntoa(ip_Container.src_ip));
    printf("ip.dip: %s\n", inet_ntoa(ip_Container.dst_ip));

    printf("tcp.sport: %hu\n", ntohs(tcp_Container.src_port));
    printf("tcp.dport: %hu\n", ntohs(tcp_Container.dst_port));
    printf("Length of IP HEADER: %d, Length of TCP Header: %d\n",size_ipheader,size_tcpheader);

    data = (u_char*)(packet+SIZE_ETHER_HEADER+size_ipheader+size_tcpheader);
    printf("header->len: %d\n",header->len);
    if((SIZE_ETHER_HEADER + size_ipheader + size_tcpheader)==header->len)
        printf("NO PAYLOAD\n\n");
    else
    {
        printf("%02x %02x %02x %02x %02x....\n\n", data[0], data[1], data[2], data[3], data[4]);
    }
}

int main(int argc, char * argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int check;
    int iter = 0;
    if(argc != 2)
    {
        fprintf(stderr, "Usage: ./main [INTERFACE NAME]\n");
        return 2;
    }

    dev = argv[1];
    printf("Device : %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000000, errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    while(iter < MAXIMUM_CAPTURE_COUNT)
    {
        check = pcap_next_ex(handle, &header, &packet);
        if(check==1)
        {
            show_data(header, packet);
            iter++;
        }
        else
        {
            if(check==0)
            {
                printf("Time Expired!\n");
                return 2;
            }
            else if(check == -1)
            {
                printf("An Error Occured: %s\n", pcap_geterr(handle));
                return 2;
            }
            else if(check == -2)
            {
                printf("No More Packets in the file.\n");
                return 2;
            }
        }
    }
    //pcap_loop(handle, 10, show_data, NULL);
    //packet = pcap_next(handle, &header);
    //printf("Jacked a packet with length of [%d]\n", header.len);
    pcap_close(handle);
    return 0;
}
