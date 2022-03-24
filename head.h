#ifndef HEAD_H
#define HEAD_H


struct myStruct {
    pcap_t* handle;
    char    target_page[8];
    u_char  myMAC[ETH_ALEN];
    u_char  victimMAC[ETH_ALEN];
    u_char  gatewayMAC[ETH_ALEN];
    struct  in_addr victimIP;
    struct  in_addr gatewayIP;
} mystruct ;

struct arp_header
{
    u_int16_t       hw_type;                /* Format of hardware address  */
    u_int16_t       protocol_type;          /* Format of protocol address  */
    u_int8_t        hw_len;                 /* Length of hardware address  */
    u_int8_t        protocol_len;           /* Length of protocol address  */
    u_int16_t       opcode;                 /* ARP opcode (command)  */
    u_int8_t        sender_mac[ETH_ALEN];   /* Sender hardware address  */
    u_int16_t       sender_ip[2];           /* Sender IP address  */
    u_int8_t        target_mac[ETH_ALEN];   /* Target hardware address  */
    u_int16_t       target_ip[2];           /* Target IP address  */
};

struct ip_header {
    u_int8_t    ip_vhl;                              /* header length and version */
    #define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
    #define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
        u_int8_t    ip_tos;                          /* type of service */
        u_int16_t   ip_len;                          /* total length of the header*/
        u_int16_t   ip_id;                           /* identification */
        u_int16_t   ip_off;                          /* fragment offset field */
    #define IP_RF 0x8000                             /*reserved fragment flag*/
    #define IP_DF 0x4000                             /*dont fragment flag*/
    #define IP_MF 0x2000
    #define TCP_PROTOCOL 0x06
    #define UDP_PROTOCOL 0x11                             /*more fragment flag*/
        u_int8_t    ip_ttl;                          /* time to live */
        u_int8_t    ip_p;                            /* protocol */
        u_int16_t   ip_sum;                          /* checksum */
    struct  in_addr ip_src, ip_dst;                  /* source and dest address */
};

struct tcp_header
{
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    u_int th_seq;                   /* sequence number */
    u_int th_ack;                   /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
    #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)
    u_short th_win;                 /* window size*/
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

struct pseudo_tcp_header
{
    struct in_addr src_ip, dest_ip;
    u_char reserved;
    u_char protocol;
    u_short tcp_size;
};

struct udp_header{
    u_short udp_src_port;           /*source port*/
    u_short udp_dst_port;           /*dest port*/
    u_short udp_len;                /*UDP length*/
    u_short udp_checksum;           /*UDP check sum*/
};


#endif // HEAD_H
