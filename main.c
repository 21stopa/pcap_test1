#include <stdio.h>
#include <pcap.h>
void show_data(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("%x\n", packet[0]);
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
