#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
/* UDP Header */
struct udpheader
{
    u_int16_t udp_sport;           /* source port */
    u_int16_t udp_dport;           /* destination port */
    u_int16_t udp_ulen;            /* udp length */
    u_int16_t udp_sum;             /* udp checksum */
};
/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};
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
/* TCP Header */
struct tcpheader {
    u_short tcph_srcport;
    u_short tcph_destport;
    u_int tcph_seqnum;
    u_int tcph_acknum;
    u_char tcph_offset:4, /* offset of data in bytes */
    tcph_reserved:4;
    u_char tcph_flags;
    u_short tcph_win;
    u_short tcph_chksum;
    u_short tcph_urgptr;
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
    close(sock);
}

unsigned short in_cksum (unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp=0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short)(~sum);
}
int Spoof_ICMP() {
    char buffer[1500];

    memset(buffer, 0, 1500);


    //Step 1: Fill in the ICMP header.
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));


    //Step 2: Fill in the IP header.
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("10.0.2.5");
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader));

    //Step 3: send the spoofed packet
    send_raw_ip_packet (ip);

    return 0;
}
int Spoof_UDP() {
    char buffer[1500];

    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer +sizeof(struct ipheader));

    //Step 1: Fill in the UDP data field.
    char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
    const char *msg = "Hello Server!\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);

    //\u05bf\u05bf\u05bf\u05bfstep 2: Fill in the UDP header.

    udp->udp_sport = htons(12345);
    udp->udp_dport = htons(9090);
    udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
    udp->udp_sum = 0; /* Many OSes ignore this field, so we do not
                         calculate it. */

    //Step 3: Fill in the IP header.


    ip->iph_protocol = IPPROTO_UDP; // The value is 17.
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct udpheader) + data_len);

    //Step 4: send the spoofed packet
    send_raw_ip_packet(ip);

    return 0;
}
int Spoof_TCP() {
    char buffer[1500];
    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));
    char *data = buffer + sizeof(struct ipheader) + sizeof(struct tcpheader);
    const char *msg = "Hello Server!\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);

    // Fill in the TCP header
    tcp->tcph_srcport = htons(12345);
    tcp->tcph_destport = htons(80);
    tcp->tcph_seqnum = htonl(1);
    tcp->tcph_acknum = 0;
    tcp->tcph_offset = sizeof(struct tcpheader) / 4;
    tcp->tcph_win = htons(65535);
    tcp->tcph_chksum = 0;
    tcp->tcph_urgptr = 0;

    // Fill in the IP header
    ip->iph_ver = 4;
    ip->iph_ihl = sizeof(struct ipheader) / 4;
    ip->iph_ttl = 255;
    ip->iph_protocol = IPPROTO_TCP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader) + data_len);

    // Send the spoofed packet
    send_raw_ip_packet(ip);

    return 0;
}


int main(){
    int ans = 0;
    printf("*******************Spoof a UDP/TCP/ICMP packet******************\u05bf\u05bf*\n");
    printf("Enter 1  to spoof UDP packet.\n"
           "Enter 2  to spoof TCP packet.\n"
           "Enter 3  to spoof ICMP packet.\n"
           "Enter 0 to exit.\n");
    scanf("%d",&ans);
    while(ans!=0){
        if (ans==1) {
            Spoof_UDP();
            printf("Send fake UDP packet\n\n\n");
        }
        if(ans==2) {
            Spoof_TCP();
            printf("Send fake TCP packet\n\n\n");

        }
        if(ans==3) {
            Spoof_ICMP();
            printf("Send fake ICMP packet\n\n\n");

        }
        printf("Enter 1  to spoof UDP packet.\n"
               "Enter 2  to spoof TCP packet.\n"
               "Enter 3  to spoof ICMP packet.\n"
               "Enter 0 to exit.\n");
        scanf("%d",&ans);
    }
    printf("******************* software termination *******************\n");
    return 0;

}