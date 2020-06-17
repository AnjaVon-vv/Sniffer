// author: Von
//
// Created by Von on 2020.
//

#include <cstdio>
#include <ctime>
#include <pcap.h>
#include "sniffer.h"
#include "protocol.h"
#include "analyze.h"

#define PROM 1
//promiscuous mode

extern char filter[128]; //过滤条件
extern char *dev; //抓包设备

extern int flowTotal; //总流量计数
extern int ipv4Flow, ipv6Flow, arpFlow, rarpFlow, pppFlow;
extern int ipv4Cnt, ipv6Cnt, arpCnt, rarpCnt, pppCnt;
extern int tcpFlow, udpFlow, icmpFlow;
extern int tcpCnt, udpCnt, icmpCnt;


//以太网解析
void callback(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    analyze analyze;

    struct ethernet *eHead;
    u_short protocol;
    u_int *id = (u_int *)arg;
    char *time = ctime((const time_t*)&pcapPkt -> ts.tv_sec);

    int flow = pcapPkt -> caplen;
    flowTotal += flow;

    printf("#########################################\n");
    printf("~~~~~~~~~~~~~device: %s~~~~~~~~~~~~~\n", dev);
    printf("~~~~~~~~~~~~~filter: %s~~~~~~~~~~~~~\n", filter);
    printf("~~~~~~~~~~~~~analyze information~~~~~~~~~~~~~\n");
    printf("id: %d\n", ++(*id));
    printf("packet length: %d\n", pcapPkt -> len);
    printf("number of bytes: %d\n", flow);
    printf("receive time: %s\n", time);

    for(int i = 0; i < pcapPkt->len; i++)
    {
        printf("%02x ", packet[i]);
        if((i+1) % 16 ==0)
            printf("\n");
    }

    printf("\n\n\n");

    eHead = (struct ethernet*)packet;
    printf("************ 数据链路层 ************\n");
    printf("~~~~~~~data link layer~~~~~~~\n");
    printf("Mac source: ");
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
            printf("%02x\n", eHead -> etherHostS[i]);
        else
            printf("%02x: ", eHead -> etherHostS[i]);
    }
    printf("Mac destination: ");
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
            printf("%02x\n", eHead -> etherHostD[i]);
        else
            printf("%02x: ", eHead -> etherHostD[i]);
    }

    protocol = ntohs(eHead -> etherType);

    //pppoe 处理
    if(protocol == 0x8863)
    {
        printf("PPPOE Discovery");
        analyze.pppAnalyze(arg, pcapPkt, packet);
        pppCnt ++;
        pppFlow += flow;
    }
    if(protocol == 0x8864)
    {
        printf("PPPOE Session");
        analyze.pppAnalyze(arg, pcapPkt, packet);
        pppCnt ++;
        pppFlow += flow;
    }

    printf("************ 网络层 ************\n");
    printf("~~~~~~network layer~~~~~~\n");
    switch (protocol)
    {
        case 0x0800:
            printf("#######IPv4!\n");
            analyze.ipAnalyze(arg, pcapPkt, packet);
            ipv4Flow += flow;
            ipv4Cnt ++;
            break;
        case 0x0806:
            printf("#######ARP!\n");
            analyze.arpAnalyze(arg, pcapPkt, packet);
            arpFlow += flow;
            arpCnt ++;
            break;
        case 0x0835:
            printf("#######RARP!\n");
            rarpFlow += flow;
            rarpCnt ++;
            break;
        case 0x08DD:
            printf("#######IPv6!\n");
            ipv6Flow += flow;
            ipv6Cnt ++;
            break;
        case 0x880B:
            printf("#######PPP!\n");
            pppFlow += flow;
            pppCnt ++;
            break;
        default:
            printf("Other network layer protocol!\n");
            break;
    }
    printf("~~~~~~~~~~~~~Done~~~~~~~~~~~~~\n");
    printf("#########################################\n\n\n");
}


extern pcap_t *pcap;
//嗅探准备
int sniffer::prepareSniffer()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDev;

    struct bpf_program bp;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    //获取
    if(pcap_findalldevs(&allDev, errbuf) == -1)
        printf("No device has been found! \n");
    dev = allDev -> name;

//    dev = "eth0";

    //打开
    pcap = pcap_open_live(dev, snapLen, PROM, 0, errbuf);
    if(pcap == nullptr)
    {
        printf("Open error!\n");
        return -1;
    }

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        printf("Could not found netmask for device %s!", dev);
        net = 0;
        mask = 0;
    }

//    if(argc > 1)
//    {
//        for(int i = 1; i < argc; i++)
//        {
//            strncat(filter, argv[i], 100);
//            strncat(filter, " ", 100);
//        }
//    }

    if(pcap_compile(pcap, &bp, filter, 0, net) == -1)
    {
        printf("Could not parse filter!\n");
        return -2;
    }
    if(pcap_setfilter(pcap, &bp) == -1)
    {
        printf("Could not install filter!\n");
        return -2;
    }

//    int id = 0;
//    pcap_loop(pcap, 20, callback, (u_char *) &id); //-1 循环抓取，出错停止

//    pcap_close(pcap);

    return 0;
}

//抓取数据包，传入抓取数量
//-1 循环抓取，出错停止
void sniffer::startSniffer(int num)
{
    int id = 0;
    pcap_loop(pcap, num, callback, (u_char *) &id);

    pcap_close(pcap);
}

//停止循环
void sniffer::stopSniffer()
{
    pcap_breakloop(pcap);
}

////嗅探测试主函数
//int main()
//{
//    sniffer s;
//    if(s.prepareSniffer() == 0)
//        s.startSniffer(20);
//    printf("Total flow: %d", flowTotal);
//    printf("IPv4 flow: %d, ARP flow: %d, IPv6 flow: %d, RARP flow: %d, PPP flow: %d\n", ipv4Flow, arpFlow, ipv6Flow, rarpFlow, pppFlow);
//    printf("IPv4 Cnt: %d, ARP Cnt: %d, IPv6 Cnt: %d, RARP Cnt: %d, PPP Cnt: %d\n", ipv4Cnt, arpCnt, ipv6Cnt, rarpCnt, pppCnt);
//    printf("TCP flow: %d, UDP flow: %d, ICMP flow: %d\n", ipv4Flow, arpFlow, ipv6Flow, rarpFlow, pppFlow);
//    printf("TCP Cnt: %d, UDP Cnt: %d, ICMP Cnt: %d\n", ipv4Cnt, arpCnt, ipv6Cnt, rarpCnt, pppCnt);
//    return 0;
//}
