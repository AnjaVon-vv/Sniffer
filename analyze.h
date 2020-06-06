//class analyze {
//};
// author: Von
//
// Created by Von on 2020.
//

#include <cstdio>
#include <iostream>
#include <ctime>
#include <sys/types.h>
#include <netinet/in.h>
#include <cstring>
#include <pcap.h>
using namespace std;
#include "protocol.h"

char *tcpFlag(const u_char tcpFlags);

extern char filter[128]; //过滤条件
extern char *dev; //抓包设备


//pppoe协议头分析
void pppAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct ppp *pHead = (struct ppp *)(packet + ethernetHead);
    printf("Version: %d\n", (pHead -> pppVT & 0xf0) >> 4);
    printf("Type: %d\n", pHead -> pppVT & 0x0f);
    printf("Code: %d\n", pHead -> pppCode);
    printf("Session ID: %d\n", ntohs(pHead -> pppSessionId));
    printf("Payload Length: %d\n", ntohs(pHead -> pppLen));
}

//arp协议头分析
void arpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct arp *aHead = (struct arp *)(packet + ethernetAddr);

    printf("Hardware type: %s\n", (ntohs(aHead -> arpHardware) == 0x0001) ? "Ethernet": "Unknown");
    printf("Protocol type: %s\n", (ntohs(aHead -> arpProtocol) == 0x0800) ? "IPv4": "Unknown");
    printf("Operation: %s\n", (ntohs(aHead -> arpOperation) == arpRequest) ? "ARP request": "ARP reply");

    printf("MAC source: ");
    for(int i = 0; i < ethernetAddr; i++)
        printf("%02x: ", aHead -> arpSM[i]);
    printf("IP source");
    for(int i = 0; i < ipAddr; i++)
        printf("%d.", aHead -> arpSI[i]);
    printf("MAC destination: ");
    for(int i = 0; i < ethernetAddr; i++)
        printf("%02x: ", aHead -> arpDM[i]);
    printf("IP destination");
    for(int i = 0; i < ipAddr; i++)
        printf("%d.", aHead -> arpDI[i]);
    printf("\n\n");
}

//icmp协议头分析
void icmpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct icmp *icmpHead = (struct icmp *)(packet + ethernetAddr + ipHead(packet));
    u_char icmpType = icmpHead -> icmpType;

    printf("ICMP type: %d  ", icmpHead -> icmpType);
    switch (icmpType)
    {
        case 0x08:
            printf("(ICMP request)\n");
            break;
        case 0x00:
            printf("(ICMP response)\n");
        case 0x11:
            printf("(Timeout!)\n");
            break;
    }
    printf("ICMP code: %d\n", icmpHead -> icmpCode);
    printf("ICMP check summary: %d\n", icmpHead -> icmpCkSum);
}

//tcp标志位分析
char *tcpFlagAnalyze(const u_char tcpFlags)
{
    char flags[100] = "-";
    if((tcpCWR & tcpFlags) == tcpCWR)
        strncat(flags, "CWR: ", 100);
    if((tcpECE & tcpFlags) == tcpECE)
        strncat(flags, "ECE: ", 100);
    if((tcpURG & tcpFlags) == tcpURG)
        strncat(flags, "URG: ", 100);
    if((tcpACK & tcpFlags) == tcpACK)
        strncat(flags, "ACK: ", 100);
    if((tcpPSH & tcpFlags) == tcpPSH)
        strncat(flags, "PSH: ", 100);
    if((tcpRST & tcpFlags) == tcpRST)
        strncat(flags, "RST: ", 100);
    if((tcpSYN & tcpFlags) == tcpSYN)
        strncat(flags, "SYN: ", 100);
    if((tcpFIN & tcpFlags) == tcpFIN)
        strncat(flags, "FIN: ", 100);
    return flags;
}

//tcp协议头分析
void tcpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct tcp *tHead = (struct tcp *)(packet + ethernetAddr + ipHead(packet));

    printf("Source port: %d\n", ntohs(tHead -> tcpS));
    printf("Destination port: %d\n", ntohs(tHead -> tcpD));
    printf("Sequence number: %d\n", ntohs(tHead -> tcpSeq));
    printf("Acknowledge number: %d\n", ntohs(tHead -> tcpAck));
    printf("Header length: %d\n", (tHead -> tcpHR & 0xf0) >> 4);
    printf("Flag: %d\n", tHead -> tcpFlag);
    printf("Flags: %d\n", tcpFlagAnalyze(tHead -> tcpFlag));
    printf("Window: %d\n", ntohs(tHead -> tcpWin));
    printf("Check summary: %d\n", ntohs(tHead -> tcpCkSum));
    printf("Urgent pointer: %d\n", ntohs(tHead -> tcpUrgP));
}

//udp协议头分析
void udpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct udp *uHead = (struct udp *)(packet + ethernetAddr + ipHead(packet));

    printf("Source port: %d\n", ntohs(uHead -> udpS));
    printf("Destination port: %d\n", ntohs(uHead -> udpD));
    printf("UDP length: %d\n", ntohs(uHead -> udpLen));
    printf("UDP check summary: %d\n", ntohs(uHead -> udpCkSum));
}

//ip协议头分析
void ipAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct ip *ipHead;
    ipHead = (struct ip *)(packet + ethernetAddr);

    printf("Version: %d\n", (ipHead -> ipHV & 0xf0) >> 4);
    printf("Head Length: %d\n", ipHead -> ipHV & 0x0f);
    printf("Type of Service: %d\n", ipHead -> ipTos);
    printf("Total Length: %d\n", ipHead -> ipLen);
    printf("Identification: %d\n", ipHead -> ipId);
    printf("Offset: %d\n", ipHead -> ipOffset);
    printf("Time to Live: %d\n", ipHead -> ipTtl);
    printf("Protocol: %d\n", ipHead -> ipProtocol);
    printf("Check Summary: %d\n", ipHead -> ipCkSum);

    printf("IP source: ");
    for(int i = 0; i < ipAddr; i++)
        cout << ipHead -> ipS[i];
    printf("\nIP destination: ");
    for(int i = 0; i < ipAddr; i++)
        cout << ipHead -> ipD[i];
    printf("\n");

    u_char protocol = ipHead -> ipProtocol;
    if(protocol == 0x01)
    {
        printf("ICMP!\n");
        icmpAnalyze(arg, pcapPkt, packet);
    }


    /****************** 传输层 ******************/
    printf("~~~~~~~transport layer~~~~~~~\n");
    switch (protocol)
    {
        case 0x06:
            printf("!\n");
            tcpAnalyze(arg, pcapPkt, packet);
            break;
        case 0x11:
            printf("!\n");
            udpAnalyze(arg, pcapPkt, packet);
            break;
        case 0x02:
            printf("IGMP!\n");
            break;
        default:
            printf("Other Transport Layer protocol!\n");
            break;
    }
}

//以太网解析
void ethernetAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct ethernet *eHead;
    u_short protocol;
    u_int *id = (u_int *)arg;
    char *time = ctime((const time_t*)&pcapPkt -> ts.tv_sec);

    printf("~~~~~~~device: %s~~~~~~~\n", dev);
    printf("~~~~~~~filter: %s~~~~~~~\n", filter);
    printf("~~~~~~~analyze information~~~~~~~\n");
    printf("id: %d\n", ++(*id));
    printf("packet length: %d\n", pcapPkt -> len);
    printf("number of bytes: %d\n", pcapPkt -> caplen);
    printf("receive time: %s\n", time);

    for(int i = 0; i < pcapPkt->len; i++)
    {
        printf("%02x", packet[i]);
        if((i+1) % 16 ==0)
            printf("\n");
    }

    printf("\n\n\n");

    eHead = (struct ethernet*)packet;
    /****************** 数据链路层 ******************/
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
        pppAnalyze(arg, pcapPkt, packet);
    }
    if(protocol == 0x8864)
    {
        printf("PPPOE Session");
        pppAnalyze(arg, pcapPkt, packet);
    }

    /****************** 网络层 ******************/
    printf("~~~~~~network layer~~~~~~\n");
    switch (protocol)
    {
        case 0x0800:
            printf("IPv4!\n");
            ipAnalyze(arg, pcapPkt, packet);
            break;
        case 0x0806:
            printf("ARP!\n");
            arpAnalyze(arg, pcapPkt, packet);
            break;
        case 0x0835:
            printf("RARP!\n");
            break;
        case 0x08DD:
            printf("IPv6!\n");
            break;
        case 0x880B:
            printf("PPP!\n");
            break;
        default:
            printf("Other network layer protocol!\n");
            break;
    }
    printf("~~~~~~~Done~~~~~~~\n\n\n");
}