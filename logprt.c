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

void print_pcap_pkt(My_pkthdr *packet) {
    static int count = 0;
    static long first_sec, first_usec;
    static long c_sec, c_usec;
    if (packet == NULL) {
        return;
    }
    if (count == 0) {
        first_sec = packet->ts.tv_sec;
        first_usec = packet->ts.tv_usec;
    }
    c_sec =  packet->ts.tv_sec - first_sec;
    c_usec = packet->ts.tv_usec - first_usec;
    while (c_usec < 0) {
        c_usec += 1000000;
        c_sec--;
    }

    printf("Packet %d\n", count);
    printf("%05ld.%06ld\n", c_sec, c_usec);
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

int openfile(char *file, char type) {   // r, w, a
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

int main(int argc, char **argv) {
    if (argc <  2) {
        fprintf(stderr, "Usage:  $ logprt <logfile>\ni.e. logprt logs/*\n");
        exit(1);
    }
    Pcap_file_header *pcap_header;
    My_pkthdr *packet_header;
    int cval;
    int len = 0;

    int fd = openfile(argv[1], 'r');
    pcap_header = read_struct(fd, sizeof(Pcap_file_header), &len);
    print_pcap_header(pcap_header);

    while ( (packet_header = read_struct(fd, sizeof(My_pkthdr), &len)) != NULL) {
        void *packet = read_struct(fd, packet_header->caplen, &len);
        print_pcap_pkt(packet_header);
        printf("\n\n");
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
