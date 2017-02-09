#include "logprt.h"

void * read_struct(int fd, int size, int *bytes_read) {
    if (size > MAXMALLOC) {
        return 0;
    }
    void *buf = malloc(size);
    *bytes_read = read(fd, buf, size);
    if (*bytes_read == -1) {
        perror("read error");
        exit(1);
    }
    else if (*bytes_read == 0) {
        free(buf);
        return 0;
    }else if (*bytes_read < size) {
        free(buf);
        printf("UNKONWN RECORD TYPE\n");
        return 0;
    }
    return buf;
}

char * get_ethernet_output(int type){
    switch (ntohs(type))
    {
        case ETH_TYPE_PUP: return "PUP";
        case ETH_TYPE_IP: return "IP";
        case ETH_TYPE_ARP: return "ARP";
        case ETH_TYPE_REVARP: return "REVARP";
        case ETH_TYPE_8021Q: return "8021Q";
        case ETH_TYPE_IPV6: return "IPV6";
        case ETH_TYPE_MPLS: return "MPLS";
        case ETH_TYPE_MPLS_MCAST: return "MPLS_MCAST";
        case ETH_TYPE_PPPOEDISC: return "PPPOEDISC";
        case ETH_TYPE_PPPOE: return "PPPOE";
        case ETH_TYPE_LOOPBACK: return "LOOPBACK";
        default: return "UNKNOWN";
    }
}

State process_eth_hdr(Eth_hdr *ethhdr, int size) {
    char *output;
    State state;
    if (size < sizeof(Eth_hdr)) {
        output = "UNKNOWN ETH";
        printf("   %s\n", output);
        return END;
    }
    output = get_ethernet_output(ethhdr->eth_type);
    if ( ntohs(ethhdr->eth_type) == ETH_TYPE_IP) {
        state = IP;
    }else if ( ntohs(ethhdr->eth_type) == ETH_TYPE_ARP) {
        state = ARP;
    }else{
        state = END;
    }
    printf("Ethernet Header\n   %s\n", output);
    return state;
}

State process_ip_hdr(Ip_hdr *iphdr, int size) {
    char *output;
    if (size < sizeof(Ip_hdr)) {
        output = "UNKNOWN";
        printf("      %s\n", output);
        return END;
    }
    if ( iphdr->ip_p == IP_PROTO_ICMP) {
        output = "ICMP";
    }else if ( iphdr->ip_p == IP_PROTO_IGMP) {
        output = "IGMP";
    }else if ( iphdr->ip_p == IP_PROTO_TCP) {
        output = "TCP";
    } else if ( iphdr->ip_p == IP_PROTO_UDP) {
        output = "UDP";
    } else {
        output = "UNRECOGNIZED";
    }
    printf("      %s\n", output);
    return END;
}

State process_arp_hdr(Arp_hdr *arphdr, int size) {
    char *output;
    if (size < sizeof(Arp_hdr)) {
        output = "UNKNOWN";
        printf("      %s\n", output);
        return END;
    }
    if ( ntohs(arphdr->ar_op) == ARP_OP_REQUEST) {
        output = "Arp Request";
    }else if ( ntohs(arphdr->ar_op) == ARP_OP_REPLY) {
        output = "Arp Reply";
    }else if ( ntohs(arphdr->ar_op) == ARP_OP_REVREQUEST) {
        output = "Arp Request";
    } else if ( ntohs(arphdr->ar_op) == ARP_OP_REVREPLY) {
        output = "Arp Reply";
    } else {
        output = "UNRECOGNIZED";
    }
    printf("      arp operation = %s\n", output);
    return END;
}

void print_pcap_pkt(My_pkthdr *packet) {
    static int count = 0;
    static unsigned int first_sec, first_usec;
    unsigned int c_sec, c_usec;
    if (packet == NULL) {
        return;
    }
    if (count == 0) {
        first_sec = packet->ts.tv_sec;
        first_usec = packet->ts.tv_usec;
    }
    c_sec = packet->ts.tv_sec - first_sec;
    c_usec = packet->ts.tv_usec - first_usec;
    while (c_usec < 0) {
        c_usec += 1000000;
        c_sec--;
    }


    printf("Packet %d\n", count);
    printf("%05u.%06u\n", c_sec, c_usec);
    printf("Captured Packet Length = %d\n", packet->caplen);
    printf("Actual Packet Length = %d\n", packet->len);
    count++;
}

void print_pcap_header(Pcap_file_header * pcap_header) {
    if (pcap_header == NULL) {
        return;
    }
    printf("PCAP_MAGIC\nVersion major number = %d\n", pcap_header->version_major);
    printf("Version minor number = %d\n", pcap_header->version_minor);
    printf("GMT to local correction = %d\n", pcap_header->thiszone);
    printf("Timestamp accuracy = %d\n",  pcap_header->sigfigs);
    printf("Snaplen = %d\n",  pcap_header->snaplen);
    printf("linktype = %d\n\n\n",  pcap_header->linktype);
}

int openfile(char *file, char type) {
    int flags, fd;
    if (type == 'r')
        flags = O_RDONLY;
    else if (type == 'w')
        flags = O_TRUNC | O_WRONLY | O_CREAT;
    else if (type == 'a')
        flags = O_APPEND | O_WRONLY | O_CREAT;
    fd = open(file, flags, 0644);
    if (fd == -1) {
        perror(file);
        exit(1);
    }
    return fd;
}

void process_packet(void * packet, int size){
    int size2 = size - sizeof(Eth_hdr);
    State state = ETHERNET;
    while (1) {
        if (state == ETHERNET) {
            state = process_eth_hdr((Eth_hdr *) packet, size);
            if (state != END)
                packet = ((Eth_hdr *) packet) + 1;
        } else if (state == IP) {
            state = process_ip_hdr((Ip_hdr *) packet, size2);
        } else if (state == ARP) {
            state = process_arp_hdr((Arp_hdr *) packet, size2);
        } else if (state == END) {
            break;
        }
    }
    printf("\n\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: prtlog <logfile>\ni.e.  $ prtlog logs/*\n");
        exit(1);
    }
    Pcap_file_header *pcap_header;
    My_pkthdr *packet_header;
    int cval;
    int len, read_len = 0;

    int fd = openfile(argv[1], 'r');
    pcap_header = read_struct(fd,sizeof(Pcap_file_header), &len);
    print_pcap_header(pcap_header);

    while ((packet_header = read_struct(fd, sizeof(My_pkthdr), &len)) != NULL) {
        void *packet = read_struct(fd, packet_header->caplen, &read_len);

        print_pcap_pkt(packet_header);

        process_packet(packet, read_len);
        free(packet_header);
        free(packet);
    }
    free(pcap_header);
    cval = close(fd);
    if (cval == -1) {
        perror("close error");
        exit(1);
    }
    exit(0);
}




