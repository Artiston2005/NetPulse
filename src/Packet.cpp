#include "Packet.h"
#include <sstream>
#include <iomanip>

std::string TcpHeader::flagsString() const {
    std::string res;
    if (flagSYN) res += "SYN, ";
    if (flagACK) res += "ACK, ";
    if (flagFIN) res += "FIN, ";
    if (flagRST) res += "RST, ";
    if (flagPSH) res += "PSH, ";
    if (flagURG) res += "URG, ";
    if (flagECE) res += "ECE, ";
    if (flagCWR) res += "CWR, ";
    if (!res.empty()) {
        res.pop_back();
        res.pop_back();
    }
    return res.empty() ? "[None]" : "[" + res + "]";
}

std::string IcmpHeader::typeDescription() const {
    switch (type) {
        case 0: return "Echo (ping) Reply";
        case 3:
            switch (code) {
                case 0: return "Dest Unreachable (Net Unreachable)";
                case 1: return "Dest Unreachable (Host Unreachable)";
                case 3: return "Dest Unreachable (Port Unreachable)";
                default: return "Destination Unreachable";
            }
        case 8: return "Echo (ping) Request";
        case 11: return "Time Exceeded (TTL expired in transit)";
        default: return "ICMP Type " + std::to_string(type);
    }
}

std::vector<ProtocolNode> ParsedPacket::getDissectionTree() const {
    std::vector<ProtocolNode> tree;

    // 1. Frame Node
    {
        ProtocolNode frameNode;
        frameNode.title = "Frame " + std::to_string(id) + ": " + 
                          std::to_string(rawBytes.size()) + " bytes on wire (" + 
                          std::to_string(rawBytes.size() * 8) + " bits)";
        frameNode.fields.push_back({"Packet ID", std::to_string(id)});
        frameNode.fields.push_back({"Arrival Time", timestampStr});
        frameNode.fields.push_back({"Epoch Delta", std::to_string(timestampRel) + " seconds"});
        frameNode.fields.push_back({"Frame Length", std::to_string(rawBytes.size()) + " bytes"});
        frameNode.fields.push_back({"Capture Length", std::to_string(rawBytes.size()) + " bytes"});
        tree.push_back(frameNode);
    }

    // 2. Ethernet Node (if link is Ethernet)
    if (linkType == LinkType::ETHERNET && !eth.srcMac.empty()) {
        ProtocolNode ethNode;
        ethNode.title = "Ethernet II, Src: " + eth.srcMac + ", Dst: " + eth.dstMac;
        ethNode.fields.push_back({"Destination MAC", eth.dstMac});
        ethNode.fields.push_back({"Source MAC", eth.srcMac});
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << eth.etherType;
        if (eth.etherType == 0x0800) ss << " (IPv4)";
        else if (eth.etherType == 0x86DD) ss << " (IPv6)";
        else if (eth.etherType == 0x0806) ss << " (ARP)";
        ethNode.fields.push_back({"Type", ss.str()});
        tree.push_back(ethNode);
    }

    // 3. Network Layer
    if (netProto == NetProto::ARP) {
        ProtocolNode arpNode;
        arpNode.title = "Address Resolution Protocol (" + 
                        std::string(arp.opcode == 1 ? "request" : "reply") + ")";
        arpNode.fields.push_back({"Hardware type", "Ethernet (1)"});
        arpNode.fields.push_back({"Protocol type", "IPv4 (0x0800)"});
        arpNode.fields.push_back({"Opcode", arp.opcode == 1 ? "request (1)" : "reply (2)"});
        arpNode.fields.push_back({"Sender MAC address", arp.senderMac});
        arpNode.fields.push_back({"Sender IP address", arp.senderIp});
        arpNode.fields.push_back({"Target MAC address", arp.targetMac});
        arpNode.fields.push_back({"Target IP address", arp.targetIp});
        tree.push_back(arpNode);
    } else if (netProto == NetProto::IPV4) {
        ProtocolNode ipNode;
        ipNode.title = "Internet Protocol Version 4, Src: " + ip4.srcIp + ", Dst: " + ip4.dstIp;
        ipNode.fields.push_back({"Version", std::to_string(ip4.version)});
        ipNode.fields.push_back({"Header Length", std::to_string(ip4.ihl * 4) + " bytes (" + std::to_string(ip4.ihl) + ")"});
        ipNode.fields.push_back({"Differentiated Services Field", "0x" + std::to_string(ip4.tos)});
        ipNode.fields.push_back({"Total Length", std::to_string(ip4.totalLength)});
        std::stringstream idSs;
        idSs << "0x" << std::hex << ip4.id << " (" << std::dec << ip4.id << ")";
        ipNode.fields.push_back({"Identification", idSs.str()});
        
        std::string flagsStr = "";
        if (ip4.flagDF) flagsStr += "Don't fragment, ";
        if (ip4.flagMF) flagsStr += "More fragments, ";
        if (flagsStr.empty()) flagsStr = "None"; else { flagsStr.pop_back(); flagsStr.pop_back(); }
        ipNode.fields.push_back({"Flags", flagsStr});
        ipNode.fields.push_back({"Fragment Offset", std::to_string(ip4.fragmentOffset)});
        ipNode.fields.push_back({"Time to Live (TTL)", std::to_string(ip4.ttl)});
        
        std::string protoStr = std::to_string(ip4.protocol);
        if (ip4.protocol == 6) protoStr += " (TCP)";
        else if (ip4.protocol == 17) protoStr += " (UDP)";
        else if (ip4.protocol == 1) protoStr += " (ICMP)";
        ipNode.fields.push_back({"Protocol", protoStr});
        
        std::stringstream csumSs;
        csumSs << "0x" << std::hex << ip4.checksum;
        ipNode.fields.push_back({"Header Checksum", csumSs.str()});
        ipNode.fields.push_back({"Source Address", ip4.srcIp});
        ipNode.fields.push_back({"Destination Address", ip4.dstIp});
        tree.push_back(ipNode);
    } else if (netProto == NetProto::IPV6) {
        ProtocolNode ipNode;
        ipNode.title = "Internet Protocol Version 6, Src: " + ip6.srcIp + ", Dst: " + ip6.dstIp;
        ipNode.fields.push_back({"Version", "6"});
        ipNode.fields.push_back({"Traffic Class", std::to_string(ip6.trafficClass)});
        ipNode.fields.push_back({"Flow Label", std::to_string(ip6.flowLabel)});
        ipNode.fields.push_back({"Payload Length", std::to_string(ip6.payloadLength)});
        ipNode.fields.push_back({"Next Header", std::to_string(ip6.nextHeader)});
        ipNode.fields.push_back({"Hop Limit", std::to_string(ip6.hopLimit)});
        ipNode.fields.push_back({"Source Address", ip6.srcIp});
        ipNode.fields.push_back({"Destination Address", ip6.dstIp});
        tree.push_back(ipNode);
    }

    // 4. Transport Layer
    if (transProto == TransProto::TCP) {
        ProtocolNode tcpNode;
        tcpNode.title = "Transmission Control Protocol, Src Port: " + std::to_string(tcp.srcPort) + 
                        ", Dst Port: " + std::to_string(tcp.dstPort) + ", Seq: " + 
                        std::to_string(tcp.seqNum) + ", Ack: " + std::to_string(tcp.ackNum);
        tcpNode.fields.push_back({"Source Port", std::to_string(tcp.srcPort)});
        tcpNode.fields.push_back({"Destination Port", std::to_string(tcp.dstPort)});
        tcpNode.fields.push_back({"Sequence Number", std::to_string(tcp.seqNum)});
        tcpNode.fields.push_back({"Acknowledgment Number", std::to_string(tcp.ackNum)});
        tcpNode.fields.push_back({"Header Length", std::to_string(tcp.dataOffset * 4) + " bytes"});
        tcpNode.fields.push_back({"Flags", tcp.flagsString()});
        tcpNode.fields.push_back({"Window Size", std::to_string(tcp.windowSize)});
        std::stringstream csum;
        csum << "0x" << std::hex << tcp.checksum;
        tcpNode.fields.push_back({"Checksum", csum.str()});
        tcpNode.fields.push_back({"Urgent Pointer", std::to_string(tcp.urgentPointer)});
        tree.push_back(tcpNode);
    } else if (transProto == TransProto::UDP) {
        ProtocolNode udpNode;
        udpNode.title = "User Datagram Protocol, Src Port: " + std::to_string(udp.srcPort) + 
                        ", Dst Port: " + std::to_string(udp.dstPort);
        udpNode.fields.push_back({"Source Port", std::to_string(udp.srcPort)});
        udpNode.fields.push_back({"Destination Port", std::to_string(udp.dstPort)});
        udpNode.fields.push_back({"Length", std::to_string(udp.length)});
        std::stringstream csum;
        csum << "0x" << std::hex << udp.checksum;
        udpNode.fields.push_back({"Checksum", csum.str()});
        tree.push_back(udpNode);
    } else if (transProto == TransProto::ICMP) {
        ProtocolNode icmpNode;
        icmpNode.title = "Internet Control Message Protocol (" + icmp.typeDescription() + ")";
        icmpNode.fields.push_back({"Type", std::to_string(icmp.type) + " (" + icmp.typeDescription() + ")"});
        icmpNode.fields.push_back({"Code", std::to_string(icmp.code)});
        std::stringstream csum;
        csum << "0x" << std::hex << icmp.checksum;
        icmpNode.fields.push_back({"Checksum", csum.str()});
        tree.push_back(icmpNode);
    }

    // 5. Application Layer
    if (appProto == AppProto::DNS) {
        ProtocolNode dnsNode;
        dnsNode.title = "Domain Name System (" + std::string(dns.isResponse ? "response" : "query") + ")";
        std::stringstream txSs;
        txSs << "0x" << std::hex << dns.txId;
        dnsNode.fields.push_back({"Transaction ID", txSs.str()});
        dnsNode.fields.push_back({"Type", dns.isResponse ? "Standard query response" : "Standard query"});
        dnsNode.fields.push_back({"Questions", std::to_string(dns.queries.size())});
        dnsNode.fields.push_back({"Answer RRs", std::to_string(dns.answers.size())});
        for (const auto& q : dns.queries) {
            dnsNode.fields.push_back({"Query Name", q.name});
        }
        for (const auto& a : dns.answers) {
            dnsNode.fields.push_back({"Answer", a.name + " -> " + a.value});
        }
        tree.push_back(dnsNode);
    } else if (appProto == AppProto::HTTP) {
        ProtocolNode httpNode;
        if (http.isRequest) {
            httpNode.title = "Hypertext Transfer Protocol (" + http.method + " " + http.uri + ")";
            httpNode.fields.push_back({"Request Method", http.method});
            httpNode.fields.push_back({"Request URI", http.uri});
            httpNode.fields.push_back({"Request Version", http.version});
            if (!http.host.empty()) httpNode.fields.push_back({"Host", http.host});
            if (!http.userAgent.empty()) httpNode.fields.push_back({"User-Agent", http.userAgent});
        } else {
            httpNode.title = "Hypertext Transfer Protocol (" + std::to_string(http.statusCode) + " " + http.statusMessage + ")";
            httpNode.fields.push_back({"Status Code", std::to_string(http.statusCode)});
            httpNode.fields.push_back({"Status Message", http.statusMessage});
            httpNode.fields.push_back({"Content-Type", http.contentType});
            httpNode.fields.push_back({"Content-Length", std::to_string(http.contentLength)});
        }
        if (!http.bodyPreview.empty()) {
            httpNode.fields.push_back({"Payload Preview", http.bodyPreview});
        }
        tree.push_back(httpNode);
    } else if (appProto == AppProto::TLS) {
        ProtocolNode tlsNode;
        tlsNode.title = "Transport Layer Security (TLS)";
        tlsNode.fields.push_back({"Content Type", "Handshake (22)"});
        tlsNode.fields.push_back({"Handshake Type", tls.handshakeType == 1 ? "Client Hello (1)" : "Server Hello (2)"});
        if (!tls.sni.empty()) {
            tlsNode.fields.push_back({"Server Name Indication (SNI)", tls.sni});
        }
        tree.push_back(tlsNode);
    } else if (payloadLength > 0) {
        ProtocolNode rawNode;
        rawNode.title = "Data (" + std::to_string(payloadLength) + " bytes)";
        rawNode.fields.push_back({"Payload Length", std::to_string(payloadLength) + " bytes"});
        tree.push_back(rawNode);
    }

    return tree;
}
