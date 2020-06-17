// author: Von
//
// Created by Von on 2020.
//

#include "widget.h"
#include "ui_widget.h"

#include <QDebug>
#include <QPushButton>
#include <QTimer>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include "protocol.h"
#include "analyze.h"


#define PROM 1
//promiscuous mode

char filter[128]; //过滤条件
char *dev; //抓包设备

int flowTotal = 0; //总流量计数
int ipv4Flow = 0, ipv6Flow = 0, arpFlow = 0, rarpFlow = 0, pppFlow = 0;
int ipv4Cnt = 0, ipv6Cnt = 0, arpCnt = 0, rarpCnt = 0, pppCnt = 0;
int tcpFlow = 0, udpFlow = 0, icmpFlow = 0;
int tcpCnt = 0, udpCnt = 0, icmpCnt = 0;
int otherCnt = 0, otherFlow = 0;

//font color
QString errClr = "de7e73";
QString highClr = "A593E0";


u_int id = 0;
//以太网解析
void ethernetAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    analyze analyze;
    Ui::Widget *ui = (Ui::Widget *)arg;

    struct ethernet *eHead;
    u_short protocol;
    char *time = ctime((const time_t*)&pcapPkt -> ts.tv_sec);

    int flow = pcapPkt -> caplen;
    flowTotal += flow;

    printf("#########################################\n");
    printf("~~~~~~~~~~~~~device: %s~~~~~~~~~~~~~\n", dev);
    printf("~~~~~~~~~~~~~filter: %s~~~~~~~~~~~~~\n", filter);
    printf("~~~~~~~~~~~~~analyze information~~~~~~~~~~~~~\n");
    printf("id: %d\n", ++id);
    printf("packet length: %d\n", flow);
    printf("receive time: %s\n", time);
    QTreeWidgetItem * topInfo = new QTreeWidgetItem(QStringList() << QString::number(id) << QString("数据包长度: %1").arg(flow));
    ui->treeWidget->addTopLevelItem(topInfo);

    char tmp[3] = {0};
    QString res;
    for(int i = 0; i < pcapPkt->len; i++)
    {
        printf("%02x ", packet[i]);
        sprintf(tmp, "%02x ", packet[i]);
        res += tmp;
        if((i+1) % 16 ==0)
        {
            printf("\n");
            sprintf(tmp, "\n");
            res += tmp;
        }
    }
    QTreeWidgetItem *pInfo = new QTreeWidgetItem(QStringList() << "数据包内容" << res);
    topInfo->addChild(pInfo);
    res.clear();

    printf("\n\n");

    eHead = (struct ethernet*)packet;
    printf("************ 数据链路层 ************\n");
    printf("~~~~~~~data link layer~~~~~~~\n");
    printf("Mac source: ");
    res += "Mac source: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
        {
            printf("%02x\n", eHead -> etherHostS[i]);
            sprintf(tmp, "%02x\n", eHead -> etherHostS[i]);
            res += tmp;
        }
        else
        {
            printf("%02x:", eHead -> etherHostS[i]);
            sprintf(tmp, "%02x:", eHead -> etherHostS[i]);
            res += tmp;
        }
    }
    printf("Mac destination: ");
    res += "Mac destination: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
        {
            printf("%02x\n", eHead -> etherHostS[i]);
            sprintf(tmp, "%02x\n", eHead -> etherHostS[i]);
            res += tmp;
        }
        else
        {
            printf("%02x:", eHead -> etherHostS[i]);
            sprintf(tmp, "%02x:", eHead -> etherHostS[i]);
            res += tmp;
        }
    }
    QTreeWidgetItem * linkInfo = new QTreeWidgetItem(QStringList() << "数据链路层" << res);
    topInfo->addChild(linkInfo);
    res.clear();

    protocol = ntohs(eHead -> etherType);

    //pppoe 处理
    if(protocol == 0x8863)
    {
        printf("PPPOE Discovery");
        analyze.pppAnalyze(arg, pcapPkt, packet);
        QTreeWidgetItem *pppInfo = new QTreeWidgetItem(QStringList() << "PPPOE Discovery" << res);
        topInfo->addChild(pppInfo);
        res.clear();
        pppCnt ++;
        pppFlow += flow;
    }
    if(protocol == 0x8864)
    {
        printf("PPPOE Session");
        analyze.pppAnalyze(arg, pcapPkt, packet);
        QTreeWidgetItem *pppInfo = new QTreeWidgetItem(QStringList() << "PPPOE Session" << res);
        topInfo->addChild(pppInfo);
        res.clear();
        pppCnt ++;
        pppFlow += flow;
    }


    QStringList resList;
    QTreeWidgetItem *netInfo, *transInfo;
    printf("************ 网络层 ************\n");
    printf("~~~~~~network layer~~~~~~\n");
    switch (protocol)
    {
    case 0x0800:
        printf("#######IPv4!\n");
        res += "IPv4!\n";
        res += analyze.ipAnalyze(arg, pcapPkt, packet);
        resList = res.split('#');
        netInfo = new QTreeWidgetItem(QStringList() << "网络层" << resList[0]);
        topInfo->addChild(netInfo);
        transInfo = new QTreeWidgetItem(QStringList() << "传输层" << resList[1]);
        topInfo->addChild(transInfo);
        res.clear();
        resList.clear();
        ipv4Flow += flow;
        ipv4Cnt ++;
        break;
    case 0x0806:
        printf("#######ARP!\n");
        res += "ARP!\n";
        res += analyze.arpAnalyze(arg, pcapPkt, packet);
        arpFlow += flow;
        arpCnt ++;
        break;
    case 0x0835:
        printf("#######RARP!\n");
        res += "RARP!\n";
        rarpFlow += flow;
        rarpCnt ++;
        break;
    case 0x08DD:
        printf("#######IPv6!\n");
        res += "Pv6!\n";
        ipv6Flow += flow;
        ipv6Cnt ++;
        break;
    case 0x880B:
        printf("#######PPP!\n");
        res += "PPPOE!\n";
        pppFlow += flow;
        pppCnt ++;
        break;
    default:
        printf("Other network layer protocol!\n");
        res += "Other network layer protocol!\n";
        otherCnt ++;
        otherFlow += flow;
        break;
    }
    if(!res.isEmpty())
    {
        netInfo = new QTreeWidgetItem(QStringList() << "网络层" << res);
        topInfo->addChild(netInfo);
        res.clear();
    }

    printf("~~~~~~~~~~~~~Done~~~~~~~~~~~~~\n");
    printf("#########################################\n\n\n");
}


pcap_t *pcap;
//抓取数据包，传入抓取数量+时间
void Widget::Sniffer(int num, int ms)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDev;
    bpf_u_int32 net;
    bpf_u_int32 mask;


    //获取
    ui->textBrowser->append("Finding deveice ......");
    if(pcap_findalldevs(&allDev, errbuf) == -1)
    {
        ui->textBrowser->append(QString("<font color=\"#%1\"> No device has been found! </font>").arg(errClr));
        printf("No device has been found! \n");
    }
    dev = allDev -> name;
    ui->textBrowser->append(QString("Find the deveice: <font color=\"#%1\"> %2 </font>\n").arg(highClr).arg(dev));

    /*硬编码    dev = "eth0";*/

    //打开设备网络
    ui->textBrowser->append("Opening the device ......");
    pcap = pcap_open_live(dev, snapLen, PROM, ms, errbuf);
    if(pcap == nullptr)
    {
        ui->textBrowser->insertPlainText(QString("<font color=\"#%1\"> Open error: </font>").arg(errClr));
        ui->textBrowser->append(errbuf);
        printf("Open error: %s\n", errbuf);
    }
    ui->textBrowser->append("Device opened!\n");

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        ui->textBrowser->insertPlainText(QString("<font color=\"#%1\"> Could not found netmask for device %2! </font>").arg(errClr).arg(dev));
        printf("Could not found netmask for device %s!\n", dev);
        net = 0;
        mask = 0;
    }

    QApplication::processEvents();

    struct bpf_program bp;
    //读取过滤条件
    if(!ui->filterLine->text().isEmpty())
    {
        strcpy(filter, ui->filterLine->text().toStdString().data());
        if(pcap_compile(pcap, &bp, filter, 0, net) == -1) //编译
        {
            printf("Could not parse filter!\n");
            ui->textBrowser->append(QString("<font color=\"#%1\"> Could not parse filter! </font>").arg(errClr));
            exit(-2);
        }
        if(pcap_setfilter(pcap, &bp) == -1) //安装
        {
            printf("Could not install filter!\n");
            ui->textBrowser->append(QString("<font color=\"#%1\"> Could not install filter! </font>").arg(errClr));
            exit(-2);
        }
    }

    //开始抓取
    ui->textBrowser->append("Snaping ... ...\n");
    QApplication::processEvents();
    pcap_dispatch(pcap, num, ethernetAnalyze, (u_char *) ui);

    //关闭设备
    pcap_close(pcap);
    ui->textBrowser->append(QString("<font color=\"#%1\"> Snap over! </font>\n").arg(highClr));
}


//抓取数据包，传入抓取数量
void Widget::startSniffer(int num)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDev;
    bpf_u_int32 net;
    bpf_u_int32 mask;


    //获取
    ui->textBrowser->append("Finding deveice ......");
    if(pcap_findalldevs(&allDev, errbuf) == -1)
    {
        ui->textBrowser->append(QString("<font color=\"#%1\"> No device has been found! </font>").arg(errClr));
        printf("No device has been found! \n");
    }
    dev = allDev -> name;
    ui->textBrowser->append(QString("Find the deveice: <font color=\"#%1\"> %2 </font>\n").arg(highClr).arg(dev));

    /*硬编码    dev = "eth0";*/

    //打开设备网络
    ui->textBrowser->append("Opening the device ......");
    pcap = pcap_open_live(dev, snapLen, PROM, 0, errbuf);
    if(pcap == nullptr)
    {
        ui->textBrowser->insertPlainText(QString("<font color=\"#%1\"> Open error: </font>").arg(errClr));
        ui->textBrowser->append(errbuf);
        printf("Open error: %s\n", errbuf);
    }
    ui->textBrowser->append("Device opened!\n");

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        ui->textBrowser->insertPlainText(QString("<font color=\"#%1\"> Could not found netmask for device %2! </font>").arg(errClr).arg(dev));
        printf("Could not found netmask for device %s!\n", dev);
        net = 0;
        mask = 0;
    }

    QApplication::processEvents();

    struct bpf_program bp;
    //读取过滤条件
    if(!ui->filterLine->text().isEmpty())
    {
        strcpy(filter, ui->filterLine->text().toStdString().data());
        if(pcap_compile(pcap, &bp, filter, 0, net) == -1) //编译
        {
            printf("Could not parse filter!\n");
            ui->textBrowser->append(QString("<font color=\"#%1\"> Could not parse filter! </font>").arg(errClr));
            exit(-2);
        }
        if(pcap_setfilter(pcap, &bp) == -1) //安装
        {
            printf("Could not install filter!\n");
            ui->textBrowser->append(QString("<font color=\"#%1\"> Could not install filter! </font>").arg(errClr));
            exit(-2);
        }
    }

    //开始抓取
    ui->textBrowser->append("Snaping ... ...\n");
    QApplication::processEvents();
    pcap_loop(pcap, num, ethernetAnalyze, (u_char *) ui);

    //关闭设备
    pcap_close(pcap);
    ui->textBrowser->append(QString("<font color=\"#%1\"> Snap over! </font>\n").arg(highClr));
}


//停止循环
void Widget::stopSniffer()
{
    pcap_breakloop(pcap);
}


Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);

    ui->inputLineEdit->setValidator(new QIntValidator(-1, 1000, this));
    ui->timeLine->setValidator(new QIntValidator(-1, 1000, this));


    //开始嗅探
    connect(ui->startBtn, &QPushButton::clicked, this, [=](){
        ui->textBrowser->append(QString("<font color=\"#%1\"> Start sniffing! </font>").arg(highClr));

        if(ui->timeLine->text().isEmpty())
        {
            if(ui->inputLineEdit->text().isEmpty())
                startSniffer(-1);
            else
                startSniffer(ui->inputLineEdit->text().toInt());
        }
        else
        {
            if(ui->inputLineEdit->text().isEmpty())
                Sniffer(-1, ui->timeLine->text().toInt());
            else
                Sniffer(ui->inputLineEdit->text().toInt(), ui->timeLine->text().toInt());
        }

        ui->flowLine->setText(QString::number(flowTotal, 10));
        QStringList cntList, flowList;
        cntList << QString::number(tcpCnt) << QString::number(udpCnt) << QString::number(arpCnt) << QString::number(rarpCnt) << QString::number(ipv4Cnt) << QString::number(ipv6Cnt) << QString::number(icmpCnt) << QString::number(pppCnt);
        flowList << QString::number(tcpFlow) << QString::number(udpFlow) << QString::number(arpFlow) << QString::number(rarpFlow) << QString::number(ipv4Flow) << QString::number(ipv6Flow) << QString::number(icmpFlow) << QString::number(pppFlow);
        for(int i = 0; i < 8; i ++)
        {
            ui->tableWidget->setItem(i, 0, new QTableWidgetItem(cntList[i]));
            ui->tableWidget->setItem(i, 1, new QTableWidgetItem(flowList[i]));
        }
    });

    //停止
    connect(ui->stopBtn, &QPushButton::clicked, this, [=](){
        stopSniffer();
        ui->textBrowser->append(QString("<font color=\"#%1\"> Sniffing stoped! </font>").arg(highClr));
    });

    //清屏
    connect(ui->clrB, &QPushButton::clicked, this, [=](){ui->textBrowser->clear();});
    connect(ui->clrF, &QPushButton::clicked, this, [=](){
        ui->tableWidget->clearContents();
        ui->flowLine->clear();
    });
    connect(ui->clrT, &QPushButton::clicked, this, [=](){
        ui->treeWidget->clear();
        id = 0;
    });

    //table widget
    ui->tableWidget->setColumnCount(2);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList() << "包数量 / 个" << "流量 / Bytes");
    ui->tableWidget->horizontalHeader()->setStyleSheet("QHeaderView::section{font:bold 'Cantarell Bold Italic';color: #FBD14B;}");
    ui->tableWidget->setRowCount(8);
    ui->tableWidget->setVerticalHeaderLabels(QStringList() << "TCP" << "UDP" << "ARP" << "RARP" << "IPv4" << "IPv6" << "ICMP" << "PPPOE");
    ui->tableWidget->verticalHeader()->setStyleSheet("QHeaderView::section{font:'Cantarell Bold Italic';color: #FBD14B;}");

    //tree widget
    ui->treeWidget->setHeaderLabels(QStringList() << "ID" << "message");
    ui->treeWidget->setColumnWidth(0, 170);
}

Widget::~Widget()
{
    delete ui;
}

