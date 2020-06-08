// author: Von
//
// Created by Von on 2020.
//

#include "analyze.h"
#include <cstdio>
#include <netinet/in.h>
#include <cstring>
#include <pcap.h>
#include "protocol.h"

extern char filter[128]; //过滤条件
extern char *dev; //抓包设备


//pppoe协议头分析
void analyze::pppAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct ppp *pHead = (struct ppp *)(packet + ethernetHead);
    printf("Version: %d\n", (pHead -> pppVT & 0xf0) >> 4);
    printf("Type: %d\n", pHead -> pppVT & 0x0f);
    printf("Code: %d\n", pHead -> pppCode);
    printf("Session ID: %d\n", ntohs(pHead -> pppSessionId));
    printf("Payload Length: %d\n", ntohs(pHead -> pppLen));
}

//arp协议头分析
void analyze::arpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
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
void analyze::icmpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
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
    char flags[100] = "";
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
    flags[99] = '\0';
    return flags;
}

//tcp协议头分析
void analyze::tcpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
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
void analyze::udpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct udp *uHead = (struct udp *)(packet + ethernetAddr + ipHead(packet));

    printf("Source port: %d\n", ntohs(uHead -> udpS));
    printf("Destination port: %d\n", ntohs(uHead -> udpD));
    printf("UDP length: %d\n", ntohs(uHead -> udpLen));
    printf("UDP check summary: %d\n", ntohs(uHead -> udpCkSum));
}

//ip协议头分析
void analyze::ipAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
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
        printf("%d", ipHead -> ipS[i]);
    printf("\nIP destination: ");
    for(int i = 0; i < ipAddr; i++)
        printf("%d", ipHead -> ipD[i]);
    printf("\n");

    u_char protocol = ipHead -> ipProtocol;
    if(protocol == 0x01)
    {
        printf("#######ICMP!\n");
        icmpAnalyze(arg, pcapPkt, packet);
    }


    printf("************** 传输层 **************");
    printf("~~~~~~~transport layer~~~~~~~\n");
    switch (protocol)
    {
        case 0x06:
            printf("#######TCP!\n");
            tcpAnalyze(arg, pcapPkt, packet);
            break;
        case 0x11:
            printf("#######UDP!\n");
            udpAnalyze(arg, pcapPkt, packet);
            break;
        case 0x02:
            printf("#######IGMP!\n");
            break;
        default:
            printf("Other Transport Layer protocol!\n");
            break;
    }
}


