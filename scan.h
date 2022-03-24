#ifndef SCAN_H
#define SCAN_H
#include <QObject>
#include <pcap.h>
#include <libnet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <string.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <QString>

//初始化本机
class scan : public QObject
{
    Q_OBJECT
public:
    scan();
    char* getDev();
    QString getIPv4Addr();
    QString getMAC();
private:
    char* dev;
    QString ipv4;
    QString mac;
    void find_dev();//设备信息
    void find_netcard();//查找网卡
    void find_ipv4();//查找ipv4
    void find_macaddr();//查找mac

signals:
    void send_ip_mac(char* dev, QString ipv4, QString mac);
};

#endif // SCAN_H
