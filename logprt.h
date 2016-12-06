#ifndef LOGPRT_H
#define LOGPRT_H
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "pcap.h"
#include "dnet.h"
#define MAXMALLOC 1000000

typedef struct pcap_file_header Pcap_file_header;
typedef struct eth_hdr  Eth_hdr;
typedef struct arp_hdr Arp_hdr;
typedef struct ip_hdr Ip_hdr;

/* states for state machine */
typedef enum {
    ETHERNET,
    IP,
    ARP,
    END
} State;

/* updated timeval struct */
typedef struct timev{
    unsigned int tv_sec;
    unsigned int tv_usec;
} Timev;

/* pcap packet header */
typedef struct my_pkthdr {
    Timev ts;
    int caplen;
    int len;
} My_pkthdr;

/* function prototypes */
Eth_hdr * get_eth_hdr(int fd);
int openfile(char *file, char type);
My_pkthdr * get_my_pkthdr(int fd);
Pcap_file_header * get_pcap_header(int fd);
State process_arp_hdr(Arp_hdr *arphdr, int size);
State process_eth_hdr(Eth_hdr *ethhdr, int size);
State process_ip_hdr(Ip_hdr *iphdr, int size);
void * read_struct(int fd, int size, int *bytes_read);
void print_pcap_header(Pcap_file_header * pcap_header);
void print_pcap_pkt(My_pkthdr *packet);
void process_packet(void * packet, int size);

#endif
