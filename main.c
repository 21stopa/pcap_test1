#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6
#define SIZE_ETHER_HEADER 14
typedef struct ether_header{
    u_char dst_mac[ETHER_ADDR_LEN];
    u_char src_mac[ETHER_ADDR_LEN];
    u_short ether_type;
}ETHER_HEADER;

typedef struct ip_header{
    u_char version_Hlength;
    u_char ToS;
    u_short total_Length;
    u_short id;
    u_short frag_Offset;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
}IP_HEADER;

typedef struct tcp_header{
    u_short src_port;
    u_short dst_port;
    u_int seq;
    u_int ack;
    u_char data_Offset;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgp;
}TCP_HEADER;

ETHER_HEADER ether_Container;
IP_HEADER ip_Container;
TCP_HEADER tcp_Container;
u_char* data;
void show_data(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int size_ipheader = 0;
    int size_tcpheader = 0;
    ether_Container = *(ETHER_HEADER*)packet;

    ip_Container = *(IP_HEADER*)(packet+SIZE_ETHER_HEADER);
    size_ipheader = (ip_Container.version_Hlength & 0x0f) * 4;
    if(size_ipheader < 20)
    {
        printf("invalid IP Header Length: %u bytes\n", size_ipheader);
        return ;
    }

    tcp_Container = *(TCP_HEADER*)(packet+SIZE_ETHER_HEADER+size_ipheader);
    size_tcpheader = ((tcp_Container.data_Offset >> 4) & 0x0f) * 4;
    //printf("size of tcp header: %d\n", size_tcpheader);
    //printf("length of packet: %d\n",header->len);
    if(size_tcpheader < 20)
    {
        printf("invalid TCP Header Length: %u bytes\n",size_tcpheader);
        return ;
    }
    data = (u_char*)(packet+SIZE_ETHER_HEADER+size_ipheader+size_tcpheader);

    printf("eth.smac: %x:%x:%x:%x:%x:%x\n",
           ether_Container.src_mac[0],ether_Container.src_mac[1],ether_Container.src_mac[2],ether_Container.src_mac[3],ether_Container.src_mac[4],ether_Container.src_mac[5]);
    printf("eth.dmac: %x:%x:%x:%x:%x:%x\n",
           ether_Container.dst_mac[0],ether_Container.dst_mac[1],ether_Container.dst_mac[2],ether_Container.dst_mac[3],ether_Container.dst_mac[4],ether_Container.dst_mac[5]);

    printf("ip.sip: %s\n", inet_ntoa(ip_Container.src_ip));
    printf("ip.dip: %s\n", inet_ntoa(ip_Container.dst_ip));

    printf("tcp.sport: %hu\n", ntohs(tcp_Container.src_port));
    printf("tcp.dport: %hu\n", ntohs(tcp_Container.dst_port));

    if((SIZE_ETHER_HEADER + size_ipheader + size_tcpheader)==header->len)
        printf("NO PAYLOAD\n");
    else
    {
        printf("%x %x %x %x %x....\n", data[0], data[1], data[2], data[3], data[4]);
    }
}

int main(int argc, char * argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp; // The compiled filter
    char filter_exp[] = "tcp port 80"; // The filter expression
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;

    dev = pcap_lookupdev((errbuf));

    if(dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
        return 2;
    }
    printf("Device : %s\n", dev);

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n",dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle ==NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
        return 2;
    }

    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, 10, show_data, NULL);
    //packet = pcap_next(handle, &header);
    //printf("Jacked a packet with length of [%d]\n", header.len);
    pcap_close(handle);
    return 0;
}
