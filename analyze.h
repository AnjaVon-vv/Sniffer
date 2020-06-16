// author: Von
//
// Created by Von on 2020.
//

#ifndef SNIFFER_ANALYZE_H
#define SNIFFER_ANALYZE_H

#include <sys/types.h>
#include <QString>

class analyze {
public:
    QString pppAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    QString arpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    QString icmpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    QString tcpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    QString udpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    QString ipAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
};


#endif //SNIFFER_ANALYZE_H
