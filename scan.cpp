#include "scan.h"

#include<QDebug>
#include <sstream>
#include <string>
#include <iostream>
using namespace std;
scan::scan()
{
    this->find_dev();
}

void scan::find_dev()
{
    this->find_netcard();
    this->find_ipv4();
    this->find_macaddr();
}

void scan::find_netcard()
{
    char *dev,buff[PCAP_BUF_SIZE];
    dev = pcap_lookupdev(buff);
    if(dev == NULL)
    {
        fprintf(stderr,"could not find default device:%s\n",buff);
        exit(-1);
    }

    this->dev = dev;
}

void scan::find_ipv4()
{
    //查找ip 需要先找到网卡
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    std::string str;
    if(getifaddrs(&ifaddr) == -1)
    {
        fprintf(stderr,"getinaddrs");
        exit(-1);
    }
    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr == NULL)
            continue;

        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if((strcmp(ifa->ifa_name,this->dev)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
                fprintf(stderr,"getnameinfo() failed: %s\n", gai_strerror(s));
                exit(-1);
            }
            freeifaddrs(ifaddr);
            this->ipv4 = QString(QLatin1String(host));
            break;
        }
    }

}

void scan::find_macaddr()
{
     int i, datalen;
     int sd;

     unsigned char dest_mac[6] = { 0 };

     struct sockaddr_ll device;
     struct ifreq ifr;  //定义网口的信息请求体

     bzero(&ifr, sizeof(struct ifreq));

     if ((sd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) < 0)   // 创建原始套接字
     {
         fprintf(stderr,"socket() failed to get socket descriptor for using ioctl()");
         exit(-1);
     }
     memcpy(ifr.ifr_name, this->dev, sizeof(struct ifreq));
     if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {                     //发送请求
         fprintf(stderr, "ioctl() failed to get source MAC address");
         exit(-1);
     }
     close(sd);
     memcpy(dest_mac, ifr.ifr_hwaddr.sa_data, 6);
     for(int i = 0; i < 6; i++)
     {
         this->mac += QString::number(int(dest_mac[i]), 16) + ":";
     }
     this->mac = this->mac.left(this->mac.size() - 1);
}

char* scan::getDev()
{
    return this->dev;
}

QString scan::getIPv4Addr()
{
    return this->ipv4;
}

QString scan::getMAC()
{
    return this->mac;
}

