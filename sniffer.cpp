// author: Von
//
// Created by Von on 2020.
//

#include <cstdio>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include "sniffer.h"
#include "protocol.h"
#include "analyze.h"

#define PROM 1
//promiscuous mode

extern char filter[128]; //过滤条件
extern char *dev; //抓包设备


//以太网解析
void callback(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    analyze analyze;

    struct ethernet *eHead;
    u_short protocol;
    u_int *id = (u_int *)arg;
    char *time = ctime((const time_t*)&pcapPkt -> ts.tv_sec);

    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf("~~~~~~~~~~~~~device: %s~~~~~~~~~~~~~\n", dev);
    printf("~~~~~~~~~~~~~filter: %s~~~~~~~~~~~~~\n", filter);
    printf("~~~~~~~~~~~~~analyze information~~~~~~~~~~~~~\n");
    printf("id: %d\n", ++(*id));
    printf("packet length: %d\n", pcapPkt -> len);
    printf("number of bytes: %d\n", pcapPkt -> caplen);
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
    }
    if(protocol == 0x8864)
    {
        printf("PPPOE Session");
        analyze.pppAnalyze(arg, pcapPkt, packet);
    }

    printf("************ 网络层 ************\n");
    printf("~~~~~~network layer~~~~~~\n");
    switch (protocol)
    {
        case 0x0800:
            printf("#######IPv4!\n");
            analyze.ipAnalyze(arg, pcapPkt, packet);
            break;
        case 0x0806:
            printf("#######ARP!\n");
            analyze.arpAnalyze(arg, pcapPkt, packet);
            break;
        case 0x0835:
            printf("#######RARP!\n");
            break;
        case 0x08DD:
            printf("#######IPv6!\n");
            break;
        case 0x880B:
            printf("#######PPP!\n");
            break;
        default:
            printf("Other network layer protocol!\n");
            break;
    }
    printf("~~~~~~~~~~~~~Done~~~~~~~~~~~~~\n");
    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n\n");
}


pcap_t *pcap;
//嗅探主函数
int sniffer::mainSniffer()
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
    if(pcap == NULL)
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

    int id = 0;

    //-1 循环抓取，出错停止
    pcap_loop(pcap, 20, callback, (u_char *) &id);

    pcap_close(pcap);

    return 0;
}

void sniffer::stopSniffer()
{
    pcap_close(pcap);
}

