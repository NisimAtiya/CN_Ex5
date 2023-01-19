#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <net/ethernet.h>
#include <unistd.h>
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
/* application header */

struct appheader {
    uint32_t unixtime;
    uint16_t length;
    uint16_t reserved:3,c_flag:1,s_flag:1,t_flag:1,status:10;
    uint16_t cache;
    uint16_t padding;
};
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};






void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    FILE *fp;
    fp = fopen("20730202_205915663.txt","a+");
    if(fp==NULL){
        printf("Error opening the file\n");
        exit(1);
    }
    const struct ip *ip;
    const struct tcphdr *tcp;
    struct tm *local;
    time_t t;


    ip = (struct ip *) (bytes + sizeof(struct ether_header));
    tcp = (struct tcphdr *) (bytes + sizeof(struct ether_header) + sizeof(struct ip));
    struct appheader *app = (struct appheader*)((bytes + sizeof(struct ethheader) + ip->ip_off*4 + tcp ->th_off * 4 ));

    if(tcp->th_flags & TH_PUSH) {
        fprintf(fp, "{\n");
        fprintf(fp, "\t(*) source_ip: %s,\n", inet_ntoa(ip->ip_src));
        fprintf(fp, "\t(*) dest_ip: %s,\n", inet_ntoa(ip->ip_dst));
        fprintf(fp, "\t(*) source_port: %d,\n", ntohs(tcp->th_sport));
        fprintf(fp, "\t(*) dest_port: %d,\n", ntohs(tcp->th_dport));

        t = time(NULL);
        local = localtime(&t);
        fprintf(fp, "\t(*) timestamp: %d-%d-%d %d:%d:%d,\n",
                local->tm_year + 1900, local->tm_mon + 1, local->tm_mday,
                local->tm_hour, local->tm_min, local->tm_sec);
        fprintf(fp, "\t(*) total_length: %u bytes,\n", h->len);
        fprintf(fp, "\t(*) cache_flag: %u,\n", app->c_flag);
        fprintf(fp, "\t(*) steps_flag: %u,\n", app->s_flag);
        fprintf(fp, "\t(*) type_flag: %u,\n", app->t_flag);
        fprintf(fp, "\t(*) status_code: %u,\n", app->status);
        fprintf(fp, "\t(*) cache_control: %u,\n", app->cache);
        fprintf(fp, "\t(*) data: \"");
        for (int i = 0; i < h->len; i++) {
            if (i % 16 == 0) {
                fprintf(fp, "\n\t\t");
            }
            fprintf(fp, "%02x ", bytes[i]);
        }
        fprintf(fp, "\"\n}\n");
    }
    fclose(fp);
}

int main(int argc, char *argv[])
{
    //1. Setting up the device
    char *dev, errbuf[PCAP_ERRBUF_SIZE];


    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    //2. Opening the device to sniff
    pcap_t *handle;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    //3. Traffic filtering
    struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] = "tcp";	/* The filter expression */

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }





    pcap_loop(handle, -1, packet_handler, NULL);




    pcap_close(handle);
    return(0);
}