#ifndef RECP_ARPPKT_THREAD_H
#define RECP_ARPPKT_THREAD_H

#include <QThread>
#include <QObject>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#define MAXBYTES2CAPTURE 2048

typedef struct arp_hdr {
    u_int16_t htype;        //hardware type
    u_int16_t ptype;        //protocol type
    u_char hlen;            //hardware address length
    u_char plen;            //protocol address length
    u_int16_t oper;         //operation code
    u_char sha[6];          //sendHardware address
    u_char spa[4];          //sender ip address
    u_char tha[6];          //target hardware address
    u_char tpa[4];          //target ip address
}arphdr_t;
class recv_arppkt_thread : public QThread
{
    Q_OBJECT
public:
    explicit recv_arppkt_thread(QObject *parent = nullptr);
protected:
    void run();
    void recv_pkt(char* dev);
private:
    bool flag = true;
    char* dev;
    QString ipv4;
    QString mac;
    pcap_t *handle = NULL;
public slots:
    void recv_ip_mac(char* dev, QString ipv4, QString mac);
    void stop_loop();
signals:
    void send_arp_pkt_info(QString ip,QString MAC);
};
//void dealpkt(u_char *u, const struct pcap_pkthdr *packhdr,const u_char *data);
#endif // RECP_ARPPKT_THREAD_H
