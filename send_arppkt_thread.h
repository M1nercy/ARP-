#ifndef SEND_ARPPKT_THREAD_H
#define SEND_ARPPKT_THREAD_H

#include <QThread>
#include <QObject>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <QString>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <string.h>
class send_arppkt_thread : public QThread
{
    Q_OBJECT
protected:
    void run();
public:
    explicit send_arppkt_thread(QObject *parent = nullptr);
    int send_pkt();
    void Qs2uc(QString MAC, unsigned char* mac);
    void getParam(char* dev,int op,unsigned char src_mac[6],char* src_ip_str,unsigned char dst_mac[6],
        char* dst_ip_str,unsigned char eth_dst_mac[6],unsigned char eth_src_mac[6]);
    bool flag = false;
private:
    libnet_t *net_t;
    char err_buf[LIBNET_ERRBUF_SIZE];
    unsigned long src_ip, dst_ip;
    libnet_ptag_t p_tag;

    char* dev;
    int op;
    unsigned char src_mac[6];
    char* src_ip_str;
    unsigned char dst_mac[6];
    char* dst_ip_str="0.0.0.0";
    unsigned char eth_dst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};//目的mac
    unsigned char eth_src_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};//源mac 只能使用真实mac
    int arpop = 1;

    QString srcip,dstip;
signals:
    void spkt(unsigned char dst_mac[6], QString dstip,unsigned char src_mac[6], QString srcip);
};

#endif // SEND_ARPPKT_THREAD_H
