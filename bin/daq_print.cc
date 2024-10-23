// print_packet, coppied from many of my tools using libpacket
// Victor Roemer, wtfbbqhax <viroemer@badsec.org>

#include <cstdio>
#include <cstdint>
#include <ctype.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>

#include <daq.h>
#include <packet/packet.h>
#include <packet/stats.h>
#include <packet/dns.h>

#include "daq_print.h"

#define IS_SET(flags, bit) ((flags & bit) == bit)

// From https://github.com/the-tcpdump-group/tcpdump/blob/master/nameser.h#L312

/*
 * Macros for subfields of flag fields.
 */
#define DNS_QR(flags)		((flags) & 0x8000)	/* response flag */
#define DNS_OPCODE(flags)	(((flags) >> 11) & 0xF)	/* purpose of message */
#define DNS_AA(flags)		(flags & 0x0400)	/* authoritative answer */
#define DNS_TC(flags)		(flags & 0x0200)	/* truncated message */
#define DNS_RD(flags)		(flags & 0x0100)	/* recursion desired */
#define DNS_RA(flags)		(flags & 0x0080)	/* recursion available */
#define DNS_AD(flags)		(flags & 0x0020)	/* authentic data from named */
#define DNS_CD(flags)		(flags & 0x0010)	/* checking disabled by resolver */
#define DNS_RCODE(flags)	(flags & 0x000F)	/* response code */

// Function to decode the DNS protocol
int print_dns(dns const& dns)
{
    bool is_response = DNS_QR(dns.h.flags);

    if (is_response)
    {
        printf("[dns response] [rcode:%d, id:%d, qdcount: %d, ancount: %d, nscount: %d, arcount:%d]\n",
            DNS_RCODE(dns.h.flags),
            dns.h.id,
            dns.h.qdcount,
            dns.h.ancount,
            dns.h.nscount,
            dns.h.arcount);
    }
    else
    {
        printf("[dns query] [id:%d, qdcount: %d]\n",
            dns.h.id,
            dns.h.qdcount);
    }

    // Parsing Question Section
    for (int i = 0; i < dns.h.qdcount; i++)
    {
        struct dns_query const& q = dns.questions[i];
        // FIXME: Formatting/printing the QNAME
        //struct dns_query *q = &dns.questions[i];
        // Display QNAME
        // Display QTYPE and QCLASS (assuming a structure in Packet to store this information)
        printf("[query] [label: %s, type: %d, class: %d]\n",
                q.label.c_str(),
                q.dns_qtype,
                q.dns_qclass);
    }

    // Parsing Answers Section
    for (int i = 0; i < dns.h.ancount; i++)
    {
        char addr[INET6_ADDRSTRLEN];
        std::string human;
 
        struct dns_answer const &a = dns.answers[i];
        if (a.dns_atype == 1)
        {
            inet_ntop(AF_INET, a.data.data(), addr, sizeof(addr));
            human.append(addr, strnlen(addr, INET6_ADDRSTRLEN));
        }
        else if (a.dns_atype == 28)
        {
            inet_ntop(AF_INET6, a.data.data(), addr, sizeof(addr));
            human.append(addr, strnlen(addr, INET6_ADDRSTRLEN));
        }
        else
        {
            human = a.data;
        }
        printf("[answer] [data: %s, type: %d, class %d, ttl: %d]\n",
                human.c_str(),
                a.dns_atype,
                a.dns_aclass,
                a.dns_ttl);
    //    // Display QNAME
    //    // Display QTYPE and QCLASS (assuming a structure in Packet to store this information)
    //    (void)dns[0].questions[i].dns_qtype;
    //    (void)dns[0].questions[i].dns_qclass;
    }
 
    printf("\n");
    return 0;
}

// Taken from Pcapstats BSD License
//
void print_data(uint8_t const * data, int64_t length)
{
    int i, x, j, c;
    int w = 0;

    for( i=0; length>0; length -= 16 )
    {
        c = length >= 16 ? 16 : length;
        printf("%06X  ", w);
        w+=16;

        for( j=0; j<c; j++ )
            printf("%2.02X ", data[i+j]);

        for( x = length; x<16; x++ )
            printf("   ");

        for( j=0; j<c; j++ )
            printf("%c", (isprint(data[i+j]) ? data[i+j] : '.'));

        printf("\n");
        i+=c;
    }
}

# define TH_FIN 0x01
# define TH_SYN 0x02
# define TH_RST 0x04
# define TH_PSH 0x08
# define TH_ACK 0x10
# define TH_URG 0x20

std::string print_tcpflags(Packet& p)
{
    // Fixit, should be const
    int flags = packet_tcpflags(&p);
    std::stringstream ss;
    
    if (IS_SET(flags, TH_FIN))
        ss << "F";
    if (IS_SET(flags, TH_SYN))
        ss << "S";
    if (IS_SET(flags, TH_RST))
        ss << "R";
    if (IS_SET(flags, TH_ACK))
        ss << "A";

    return ss.str();
}

void
print_packet(int const instance_id, DAQ_PktHdr_t const* hdr, uint8_t const * data, size_t const len)
{
    Packet packet;

    packet_clear(&packet);

    int error = packet_decode(&packet, data, len);
    (void)error;

    struct ipaddr src = packet_srcaddr(&packet);
    struct ipaddr dst = packet_dstaddr(&packet);
    struct ipaddr *a = &src;
    struct ipaddr *b = &dst;
    uint32_t sport = packet_srcport(&packet);
    uint32_t dport = packet_dstport(&packet);
    uint32_t proto = packet_protocol(&packet);

#ifdef PRINT_PACKET_LAYERS
    // Extra debug logging
    unsigned it;
    for (Protocol *_p = packet_proto_first(&packet, &it);
            _p; _p = packet_proto_next(&packet, &it))
    {
        printf("%s:", packet_proto_name(_p));
    }
    printf("\n");
#endif

    int version = packet_version(&packet);
    int af = AF_INET;
    if (version == 6) {
        af = AF_INET6;
    }

    char addr[INET6_ADDRSTRLEN];
    printf("[src: %s, ", inet_ntop(af, a, addr, sizeof(addr)));
    printf("dst: %s, ", inet_ntop(af, b, addr, sizeof(addr)));
    printf("proto: %d, id: %d, sp: %d, dp: %d, dlen: %u] [instance: %d]",
            proto,
            packet_id(&packet),
            sport,
            dport,
            packet_paysize(&packet),
            instance_id);


    std::string flags = print_tcpflags(packet);
    if (flags.size()) {
        printf(" [flags: %s]\n", flags.c_str());
    } else {
        printf("\n");
    }

    if (packet_is_fragment(&packet))
    {
        printf(" |ip off: %u %s\n",
                packet_frag_offset(&packet),
                packet_frag_mf(&packet) ? "mf" : "");
    }

    uint32_t max = packet_paysize(&packet);
    const uint8_t *payload = packet_payload(&packet);
    if (sport == 53 || dport == 53)
    {
        dns _dns;
        decode_dns(payload, max, &_dns);
        print_dns(_dns);
    }

    max = max > 128 ? 128 : max;
    //print_data(payload, max);

#ifdef PRINT_PACKET_STATS
    // Packet stats are useful for determining decoding errors
    struct packet_stats const * stats;
    packet_stats(&stats);

    printf("ip4 headers: %u\n"
           "ip4 badsum: %u\n"
           "ip4 tooshort: %u\n"
           "ip4 toosmall: %u\n"
           "ip4 badhlen: %u\n"
           "ip4 badlen: %u\n",
            stats->ips_packets,
            stats->ips_badsum,
            stats->ips_tooshort,
            stats->ips_toosmall,
            stats->ips_badhlen,
            stats->ips_badlen);
    printf("tcp headers: %u\n"
           "tcp badsum: %u\n"
           "tcp badoff: %u\n"
           "tcp tooshort %u\n",
            stats->tcps_packets,
            stats->tcps_badsum,
            stats->tcps_badoff,
            stats->tcps_tooshort);
#endif
}




