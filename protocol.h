// author: Von
//
// Created by Von on 2020.
//

#ifndef SNIFFER_PROTOCOL_H
#define SNIFFER_PROTOCOL_H

#include <sys/types.h>
#include <netinet/in.h>


#define snapLen 1518
//最大抓包长度
// Ethernet 1500字节 + 以太网帧头部14字节 + 以太网帧尾部4字节
#define ethernetHead 14
//以太网头 14B
#define ethernetAddr 6
//以太网地址 6B

#define ipHead(packet) ((((struct ip *)(packet + ethernetHead)) -> ipHV & 0x0f) * 4)
//ip头字节数
// 取低4位即头部长度，单位4B，强转ip结构体
#define ipAddr 4
//ip地址 4B

#define arpRequest 1
#define arpReply 2

//TCP 标志位
#define tcpFIN 0x01
#define tcpSYN 0x02
#define tcpRST 0x04
#define tcpPSH 0x08
#define tcpACK 0x10
#define tcpURG 0x20
#define tcpECE 0x40
#define tcpCWR 0x80


struct ethernet
{
    u_char etherHostD[ethernetAddr];
    u_char etherHostS[ethernetAddr];
    u_short etherType;
};

struct ip
{
    u_char ipHV; //Head Length + Version
    //head len 4, version 4
    //一起定义避免大小端判断
    u_char ipTos; //type of service
    u_short ipLen;
    u_short ipId;
    u_short ipOffset;
    u_char ipTtl;
    u_char ipProtocol;
    u_char ipCkSum;
    u_char ipS[ipAddr]; //source
    u_char ipD[ipAddr]; //destination
};

struct tcp
{
    u_short tcpS; //source port
    u_short tcpD; //destination port
    u_int tcpSeq;
    u_int tcpAck;
    u_char tcpHR; //Head Length + Reserved
    //head len 4, reserved 4
    u_char tcpFlag;
    u_short tcpWin;
    u_short tcpCkSum;
    u_short tcpUrgP;
};

struct udp
{
    u_short udpS; //source port
    u_short udpD; //destination port
    u_short udpLen;
    u_short udpCkSum;
};

struct arp
{
    u_short arpHardware; //硬件类型
    u_short arpProtocol; //上层协议类型
    u_char arpMac; //mac地址长度
    u_char arpIp; //ip地址长度
    u_short arpOperation;
    u_char arpSM[ethernetAddr]; //source mac
    u_char arpSI[ipAddr]; //source ip
    u_char arpDM[ethernetAddr]; //destination mac
    u_char arpDI[ipAddr]; //destination ip
};

struct icmp
{
    u_char icmpType;
    u_char icmpCode;
    u_short icmpCkSum;
    u_short icmpFlag;
    u_short icmpSeq;
    u_int icmpTime;
};

struct ppp //ppp over ethernet
{
    u_char pppVT; //Version + Type
    //version 0x1, type 0x1
    u_char pppCode;
    u_short pppSessionId;
    u_short pppLen;
};

#endif //SNIFFER_PROTOCOL_H