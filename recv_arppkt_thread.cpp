#include "recv_arppkt_thread.h"
#include <QDebug>
recv_arppkt_thread::recv_arppkt_thread(QObject *parent) : QThread(parent)
{

}

void recv_arppkt_thread::run()
{
    this->flag = true;
    recv_pkt(this->dev);
}

//dev网卡名
void recv_arppkt_thread::recv_pkt(char* dev)
{
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    struct bpf_program filter; /*place to store the filter program*/
    char errbuf[PCAP_BUF_SIZE];
    handle = NULL; /*interface handle*/
    char filter_char[] = "arp or rarp";
    struct pcap_pkthdr pkthdr;
    const u_char* packet = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    /*open network device for packet capture*/
    handle = pcap_open_live(dev, MAXBYTES2CAPTURE, 1, 512, errbuf);
    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }

     /*look up device network addr and mask*/
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        return;
    }

    /*complie the filter expression of filter program*/
    pcap_compile(handle, &filter, filter_char, 0, mask);
    pcap_setfilter(handle, &filter);

    /*catch packet*/
    while(flag)
    {
//        int res = pcap_next_ex(handle, &header, &pkt_data) >= 0 &&
        if((packet = pcap_next(handle, &pkthdr)) == NULL)
            continue;
        arphdr_t *arphdr = NULL;
        arphdr = (arphdr_t*)(packet + 14);
        if(ntohs(arphdr->oper) == ARPOP_REQUEST)
            continue;
        char buf[50];
        QString src_mac,dst_mac,src_ip,dst_ip;
        if (ntohs(arphdr->htype) == 1 && ntohs(arphdr->ptype) == 0x0800) {
            sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x", arphdr->sha[0], arphdr->sha[1], arphdr->sha[2],
                    arphdr->sha[3], arphdr->sha[4], arphdr->sha[5]);
            src_mac = QString(buf);
            memset(buf,0,sizeof(buf));
            sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x", arphdr->tha[0], arphdr->tha[1], arphdr->tha[2],
                    arphdr->tha[3], arphdr->tha[4], arphdr->tha[5]);
            dst_mac = QString(buf);
            memset(buf,0,sizeof(buf));
            sprintf(buf,"%d.%d.%d.%d", arphdr->spa[0], arphdr->spa[1], arphdr->spa[2],arphdr->spa[3]);
            src_ip = QString(buf);
            memset(buf,0,sizeof(buf));
            sprintf(buf,"%d.%d.%d.%d", arphdr->tpa[0], arphdr->tpa[1], arphdr->tpa[2],arphdr->tpa[3]);
            dst_ip = QString(buf);
            memset(buf,0,sizeof(buf));
            emit send_arp_pkt_info(src_ip,src_mac);
        }

    }
}

void recv_arppkt_thread::recv_ip_mac(char* dev, QString ipv4, QString mac)
{
    this->dev = dev;
    this->ipv4 = ipv4;
    this->mac = mac;

}

void recv_arppkt_thread::stop_loop()
{
    this->flag = false;
}
