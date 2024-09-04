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
 * NOTICE: TIMEOUT support in vpp DAQ only works in interrupt mode.
 */
#define TIMEOUT 100

/* STATIC_MODULES
 *
 *  Enables the support of builtin libdaq_static_vpp.la and libdaq_static_geneve.la
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

char const* str_from_verdict(DAQ_Verdict const& verdict);

namespace DAQ
{
#ifdef STATIC_MODULES
    // from libdaq_static_vpp.a
    extern "C" const DAQ_ModuleAPI_t vpp_daq_module_data;
    extern "C" const DAQ_ModuleAPI_t geneve_daq_module_data;

    static DAQ_Module_h static_modules[] =
    {
        &vpp_daq_module_data,
        &geneve_daq_module_data,
        nullptr
    };
#endif

    static char const *module_paths[] =
    {
        // Location of all the open source Snort daqs (bpf)
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
    DataPlaneWorker(DaqConfig config, unsigned id, std::string filter, DAQ_Verdict verdict, DAQ_Verdict default_verdict)
        : config(config),
          id(id),
          match_verdict(verdict),
          default_verdict(default_verdict)
    {
        if (pcap_compile_nopcap(SNAPLEN, DLT_EN10MB, &fcode, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
        {
            fprintf(stderr, "%s: BPF state machine compilation failed!", __func__);
            abort();
        }

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

        // Float these workers on cpus 3 & 4
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(3, &cpuset);
        CPU_SET(4, &cpuset);
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

        do {
            auto recv = in.receive_msgs();

            if (recv.frame.recv_count > 0) {
                print_packets(recv.frame);
            }

            if (recv.status == DAQ_RSTAT_ERROR ||
                recv.status == DAQ_RSTAT_INVALID) {
                state = STOP;
            }

            in.finalize_msgs(verdicts);

        } while(state != STOP);

        in.stop();
    }

    void stop()
    {
        state = STOP;
    }

private:
    bool filter_packet(UNUSED(DAQ_PktHdr_t const* hdr),
            uint8_t const* data,
            uint32_t const size,
            bpf_program const& fcode)
    {
        return bpf_filter(fcode.bf_insns, data, size, size) == SNAPLEN;
    }

    char const* str_from_verdict(DAQ_Verdict const& verdict)
    {
        if (verdict == DAQ_VERDICT_PASS)
            return TXT_FG_TEAL("pass");
        if (verdict == DAQ_VERDICT_BLOCK)
            return TXT_FG_RED("block");
        if (verdict == DAQ_VERDICT_WHITELIST)
            return TXT_FG_GREEN("allowlist");
        if (verdict == DAQ_VERDICT_BLACKLIST)
            return TXT_FG_PURPLE("blocklist");
        if (verdict == DAQ_VERDICT_IGNORE)
            return "ignore";
        return "";
    }

    void print_packets(DaqMsgFrame const& frame)
    {
        for (unsigned i = 0; i < frame.recv_count; i++)
        {
            auto const & msg = frame.msgs[i];
            if (msg->type == DAQ_MSG_TYPE_PACKET) {
                DAQ_PktHdr_t const * hdr = daq_msg_get_pkthdr(msg);
                uint8_t const * data = daq_msg_get_data(msg);
                uint32_t const size = daq_msg_get_data_len(msg);

                DAQ_Verdict verdict = default_verdict;
                bool matched = false;
                if (filter_packet(hdr, data, size, fcode)) {
                    verdict = match_verdict;
                    matched = true;
                }

                verdicts.verdicts[i] = verdict;
                //printf(matched ? "[" TXT_FG_PURPLE("match") "] " : "");
		printf("[%s] ", str_from_verdict(verdict));
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
};

// this is similar to how tcpdump 
static inline std::string
concat_args(int argc, char const* argv[])
{
    std::string result;
    for (int i = 0; i < argc; ++i)
    {
        if (i > 0)
        {
            result += " ";
        }
        result += argv[i];
    }
    return result;
}

static inline DAQ_Verdict
verdict_from_str(std::string const& arg)
{
    if (arg == "pass")
        return DAQ_VERDICT_PASS;

    if (arg == "block")
        return DAQ_VERDICT_BLOCK;

    if (arg == "allowlist" || arg == "whitelist")
        return DAQ_VERDICT_WHITELIST;

    if (arg == "blocklist" || arg == "blacklist")
        return DAQ_VERDICT_BLACKLIST;

    abort();
    return DAQ_VERDICT_IGNORE;
}

int main(int argc, char const* argv[])
{
    DAQ::load_modules();
    packet_set_datalink(DLT_EN10MB);

    //socketpath_t socket_path {};
    //snprintf(socket_path, sizeof(socket_path), "/tmp/snort.sock");

    DaqVars vars {
        //{ "socket_path", socket_path },
        //{ "debug", "true" },
    };

    if (argc < 2)
    {
        fprintf(stderr, "Usage: dnshog <pcap>\n");
        exit(1);
    }

    DAQ_Verdict default_verdict = DAQ_VERDICT_PASS;
    //DAQ_Verdict match_verdict = verdict_from_str(argv[1]);
    DAQ_Verdict match_verdict = verdict_from_str("pass");
    std::string filter = concat_args(argc-2, argv+2);

    DaqConfig pcap_config("pcap", argv[1], DAQ_MODE_READ_FILE, vars);
    DataPlaneWorker wk0(pcap_config, 0, filter, match_verdict, default_verdict);

    sleep(2);

    wk0.stop();
    wk0.join();

    DAQ::unload_modules();
    return 0;
}
