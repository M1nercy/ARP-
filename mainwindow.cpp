#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    initSiSl();
    initUI();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::initSiSl()
{
    qRegisterMetaType<unsigned char*>("unsigned char[6]");
    connect(sc,&scan::send_ip_mac , rpkt, &recv_arppkt_thread::recv_ip_mac);
    connect(this, &MainWindow::stop_recv_loop, rpkt, &recv_arppkt_thread::stop_loop);
    connect(rpkt, &recv_arppkt_thread::send_arp_pkt_info, this, &MainWindow::recv_arp_pkt_info);
    connect(spkt, &send_arppkt_thread::spkt, this, &MainWindow::rpktmsg);
}

void MainWindow::initUI()
{
    emit sc->send_ip_mac(sc->getDev(), sc->getIPv4Addr(), sc->getMAC());
    // local information
    ui->lineEdit_netcard->setText(QString(sc->getDev()));
    ui->lineEdit_IPv4->setText(sc->getIPv4Addr());
    ui->lineEdit_MAC->setText(sc->getMAC());

    ui->lineEdit_netcard->setFocusPolicy(Qt::NoFocus);
    ui->lineEdit_IPv4->setFocusPolicy(Qt::NoFocus);
    ui->lineEdit_MAC->setFocusPolicy(Qt::NoFocus);

    //init ip-mac
    QStringList ipmac_header;
    QTableWidgetItem* headerItem;
    ipmac_header << "IP" << "MAC";
    ui->tableWidget_ip_mac->setColumnCount(ipmac_header.count());
    for(int i = 0; i < ui->tableWidget_ip_mac->columnCount(); i++)
    {
        headerItem = new QTableWidgetItem(ipmac_header.at(i));
        QFont font = headerItem->font();
        font.setBold(true);
        font.setPointSize(10);
        headerItem->setTextColor(Qt::black);
        headerItem->setFont(font);
        ui->tableWidget_ip_mac->setHorizontalHeaderItem(i, headerItem);
    }
    ui->tableWidget_ip_mac->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget_ip_mac->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget_ip_mac->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget_ip_mac->verticalHeader()->setHidden(true);

    ui->lineEdit_IP->setText("192.168.0.1");
    ui->lineEdit_attack_srcip->setText(sc->getIPv4Addr());
    ui->lineEdit_attack_dstip->setText(sc->getIPv4Addr());
    ui->lineEdit_attack_srcMAC->setText(sc->getMAC());
    ui->lineEdit_attack_dstMAC->setText(sc->getMAC());
    ui->pushButton_scan_catch->setText("抓包：关");
    ui->pushButton_attack->setText("攻击:关");
}

void MainWindow::on_pushButton_scan_clicked()
{
    char op = 'b';
    unsigned char src_mac[6] = {0};
    spkt->Qs2uc(sc->getMAC(),src_mac);
    char* src_ip_str = sc->getIPv4Addr().toLatin1().data();
    char* dst_ip_str = const_cast<char*>(ui->lineEdit_IP->text().toStdString().c_str());
    unsigned char dst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};//广播
    spkt->getParam(sc->getDev(),op,src_mac,src_ip_str,dst_mac,dst_ip_str,dst_mac,src_mac);
    spkt->start();
}

void MainWindow::on_pushButton_scan_catch_clicked()
{
    if(!this->rpkt->isRunning())
    {
        this->rpkt->start();
        ui->pushButton_scan_catch->setText("抓包：开");
    }else{
        emit stop_recv_loop();
        ui->pushButton_scan_catch->setText("抓包：关");
    }
}

void MainWindow::recv_arp_pkt_info(QString ip,QString MAC)
{
    int row = ui->tableWidget_ip_mac->rowCount();
    ui->tableWidget_ip_mac->setRowCount(row + 1);
    ui->tableWidget_ip_mac->setItem(row,0,new QTableWidgetItem(ip));
    ui->tableWidget_ip_mac->setItem(row,1,new QTableWidgetItem(MAC));
}

void MainWindow::rpktmsg(unsigned char dst_mac[6], QString dstip,unsigned char src_mac[6],QString srcip)
{
    QString str;
    char buf[50];

    str += srcip + " is at ";

    sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x", src_mac[0], src_mac[1], src_mac[2],
                    src_mac[3], src_mac[4], src_mac[5]);
    str += QString(buf) + "\n";
    memset(buf,0,sizeof(buf));

    str += "To " + dstip + " ";

    sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x", dst_mac[0], dst_mac[1], dst_mac[2],
                    dst_mac[3], dst_mac[4], dst_mac[5]);
    str += QString(buf) + "\n----------------------------";
    memset(buf,0,sizeof(buf));

    ui->textEdit->append(str);

}

void MainWindow::on_pushButton_attack_clicked()
{
    if(!this->spkt->isRunning())
    {
        char op;
        if(ui->comboBox->currentIndex() == 0)
        {
            op = 'a';
        }
        else if(ui->comboBox->currentIndex() == 1)
        {
            op = 'c';
        }
        else {op = 'b';}
        unsigned char eth_src_mac[6],eth_dst_mac[6],src_mac[6] = {0};
        spkt->Qs2uc(sc->getMAC(),eth_src_mac);
        spkt->Qs2uc(ui->lineEdit_attack_dstMAC->text(),eth_dst_mac);
        spkt->Qs2uc(ui->lineEdit_attack_srcMAC->text(),src_mac);
        char* src_ip_str = const_cast<char*>(ui->lineEdit_attack_srcip->text().toStdString().c_str());
        char* dst_ip_str = const_cast<char*>(ui->lineEdit_attack_dstip->text().toStdString().c_str());
        spkt->getParam(sc->getDev(),op,src_mac,src_ip_str,eth_dst_mac,dst_ip_str,eth_dst_mac,eth_src_mac);
        spkt->start();
        ui->pushButton_attack->setText("攻击:开");
    }else{
        spkt->flag = false;
        ui->pushButton_attack->setText("攻击:关");
    }
}

