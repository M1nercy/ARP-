#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QMainWindow>
#include <QString>
#include <scan.h>
#include <send_arppkt_thread.h>
#include <recv_arppkt_thread.h>
#include <QMetaType>
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void arpAttack();
private:
    Ui::MainWindow *ui;
    recv_arppkt_thread* rpkt = new recv_arppkt_thread();
    scan *sc = new scan();
    send_arppkt_thread *spkt = new send_arppkt_thread();
    void initSiSl();
    void initUI();
private slots:
    void on_pushButton_scan_clicked();
    void on_pushButton_scan_catch_clicked();
    void recv_arp_pkt_info(QString ip,QString MAC);
    void on_pushButton_attack_clicked();
    void rpktmsg(unsigned char dst_mac[6], QString dstip,unsigned char src_mac[6], QString srcip);
signals:
    void stop_recv_loop();
};
#endif // MAINWINDOW_H
