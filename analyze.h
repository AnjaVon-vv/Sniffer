// author: Von
//
// Created by Von on 2020.
//

#ifndef SNIFFER_ANALYZE_H
#define SNIFFER_ANALYZE_H

#include <sys/types.h>

class analyze {
public:
    void pppAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    void arpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    void icmpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    void tcpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    void udpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
    void ipAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet);
};


#endif //SNIFFER_ANALYZE_H
