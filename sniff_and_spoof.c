#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
//#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};
/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_ids;     //Used for identifying request
    unsigned short int icmp_seqs;    //Sequence number
};
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;

    //Allows you to change things and leave things in the packet
    int enable = 1;

    // Step 1: Create a raw socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    printf("packet fake-icmp-pong send\n");
    close(sock);
}
unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}
//void spoof_reply(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
//
//    //pointers
//    struct ipheader * got_packet_ip_header = (struct ipheader *)(bytes+ 14);
//    struct icmpheader *icmp = (struct icmpheader *) (bytes + 14 + sizeof(struct ipheader));
//    //only icmp request packet
//    if(got_packet_ip_header->iph_protocol == IPPROTO_ICMP && icmp->icmp_type == 8)
//    {
//
//        char buffer[1500];
//
//        memset(buffer, 0, 1500);
//        struct ipheader *ip1 = (struct ipheader *) buffer;
//        ip1->iph_ver= 4;
//        ip1->iph_ihl = 5;
//        ip1->iph_ttl = 20;
//        //replace ip source and ip dest
//        ip1->iph_destip.s_addr = got_packet_ip_header->iph_sourceip.s_addr;
//        ip1->iph_sourceip.s_addr = got_packet_ip_header->iph_destip.s_addr;
//        struct icmpheader *icmp_our = (struct icmpheader *) (buffer + sizeof(struct ipheader));
//        icmp_our->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
//        // Calculate the checksum for integrity
//        icmp_our->icmp_chksum = 0;
//        icmp_our->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));
//        icmp_our->icmp_id = icmp->icmp_id;
//        icmp_our->icmp_seq = icmp->icmp_seq;
//        ip1->iph_protocol = IPPROTO_ICMP;
//        ip1->iph_len = htons(sizeof(struct ipheader) +
//                            sizeof(struct icmpheader));
//        send_raw_ip_packet (ip1);
//    }
//
//}
void spoof_reply(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct ethheader *eth = (struct ethheader *) bytes;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip_p = (struct ipheader *)
                (bytes + sizeof(struct ethheader));


        if (ip_p->iph_protocol == IPPROTO_ICMP) {
            struct icmpheader *icmp_p = (struct icmpheader *) ((u_char *) ip_p + sizeof(struct ipheader));
            if (icmp_p->icmp_type == ICMP_ECHO) {
                printf("An icmp packet was sniff\n\n");
                printf("ICMP From: %s\n", inet_ntoa(ip_p->iph_sourceip));
                printf("         To: %s\n", inet_ntoa(ip_p->iph_destip));

                icmp_p->icmp_type = ICMP_ECHOREPLY;//ICMP Type: 8 is request, 0 is reply.
                icmp_p->icmp_code = 0;
                icmp_p->icmp_chksum = 0;
                icmp_p->icmp_chksum = in_cksum((unsigned short *) icmp_p,
                                               ip_p->iph_len - sizeof(struct ipheader));

                int temp = ip_p->iph_sourceip.s_addr;
                ip_p->iph_sourceip.s_addr = ip_p->iph_destip.s_addr;
                ip_p->iph_destip.s_addr = temp;
                ip_p->iph_ttl=120;
                ip_p->iph_flag=0;
                ip_p->iph_ident=0;
                ip_p->iph_ver=4;
                send_raw_ip_packet(ip_p);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    //1. Setting up the device
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;


//    dev = pcap_lookupdev(errbuf);
//    if (dev == NULL) {
//        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
//        return(2);
//    }

    //2. Opening the device to sniff
    pcap_t *handle;
    handle = pcap_open_live("br-ba1bfb53f49c", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    //3. Traffic filtering
    struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] = "icmp";	/* The filter expression */

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    pcap_loop(handle, -1, spoof_reply, NULL);

    pcap_close(handle);
    return(0);
}