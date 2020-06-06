// author: Von
//
// Created by Von on 2020.
//

#include <cstdio>
#include <sys/types.h>
#include <pcap.h>
#include "protocol.h"
#include "analyze.h"

#define PROM 1
//promiscuous mode

char filter[128]; //过滤条件
char *dev; //抓包设备

int main(int argc, char *argv[])
{
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr pp;
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

    if(argc > 1)
    {
        for(int i = 1; i < argc; i++)
        {
            strncat(filter, argv[i], 100);
            strncat(filter, " ", 100);
        }
    }

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

    //循环抓取，出错停止
    pcap_loop(pcap, -1, ethernetAnalyze, (u_char *) &id);

    pcap_close(pcap);

    return 0;
}