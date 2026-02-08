# LibPacket

```
              _ _ _                      _        _
             | (_) |__  _ __   __ _  ___| | _____| |_
             | | | '_ \| '_ \ / _` |/ __| |/ / _ \ __|
             | | | |_) | |_) | (_| | (__|   <  __/ |_
             |_|_|_.__/| .__/ \__,_|\___|_|\_\___|\__|
                       |_|
```

TCP/IP packet decoder/parser that provides a clean C API to aid in the
creation of packet sniffers and analysis tools.

Release: 0.2.0
Bug reports: github.com/wtfbbqhax/LibPacket/issues

## Features

- Decode common L2/L3/L4 protocol headers with a consistent API.
- Traverse protocol layers from a decoded packet.
- Query IPv4/IPv6 addressing, transport ports, and TCP flags.
- Optional alternate payload pointer for defragmented data.

## Supported platforms

Expected to work on:

- Linux
- macOS
- FreeBSD
- OpenBSD

If it doesn't work on the listed platforms, or you would like it to work on a
different platform, please open an issue.

## Requirements

- CMake
- libpcap
- GoogleTest (gtest) for running tests

> [!IMPORTANT]
> libpcap is required to build LibPacket and for helpers like
> `packet_decode_pcap` used with pcap captures.

## Build and install

```sh
# Configure
cmake -S . -B build -G Ninja

# Build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Install
cmake --install build
```

> [!TIP]
> You can omit `-G Ninja` if you prefer your default CMake generator.

## Quick start

Minimal example decoding a pcap file and printing protocol layers:

```c
#include <stdio.h>
#include <pcap/pcap.h>
#include <packet/packet.h>

static void on_packet(uint8_t *unused, const struct pcap_pkthdr *ph,
                      const uint8_t *pkt)
{
    Packet *packet = packet_create();

    if (packet_decode(packet, pkt, ph->caplen) == 0) {
        unsigned it = 0;
        Protocol *proto = NULL;

        for (proto = packet_proto_first(packet, &it); proto != NULL;
             proto = packet_proto_next(packet, &it)) {
            printf("%s ", packet_proto_name(proto));
        }
        printf("\n");
    }

    packet_destroy(packet);
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap) {
        fprintf(stderr, "%s\n", errbuf);
        return 2;
    }

    int rc = pcap_loop(pcap, -1, on_packet, NULL);
    pcap_close(pcap);

    return rc == -1 ? 3 : 0;
}
```

## Protocol support

LibPacket supports decoding the following protocol headers:

- Ethernet
- VLAN / 802.1Q
- IPv4
- IPv6
- MPLS
- PPP
- PPPOE
- TCP
- UDP
- SCTP
- ICMP
- ICMPv6

Experimental support is provided for:

- IPX
- SPX

## API overview

Creation and decoding:

```c
Packet *packet_create(void);
void packet_destroy(Packet *packet);

int packet_decode(Packet *packet, const unsigned char *raw_data,
                  unsigned raw_data_size);
int packet_decode_pcap(Packet *packet, const uint8_t *pkt,
                       const struct pcap_pkthdr *pkthdr);
```

Protocol layers:

```c
Protocol *packet_proto_first(Packet *packet, unsigned *it);
Protocol *packet_proto_next(Packet *packet, unsigned *it);
unsigned packet_proto_count(Packet *packet);

PROTOCOL packet_proto_proto(Protocol *proto);
int packet_proto_size(Protocol *proto);
const uint8_t *packet_proto_data(Protocol *proto);
const char *packet_proto_name(Protocol *proto);
```

IPv4 and IPv6:

```c
int packet_version(Packet *packet);

struct ipaddr packet_srcaddr(Packet *packet);
struct ipaddr packet_dstaddr(Packet *packet);

uint8_t packet_protocol(Packet *packet);
uint32_t packet_id(Packet *packet);
uint8_t packet_ttl(Packet *packet);
uint8_t packet_tos(Packet *packet);

bool packet_is_fragment(Packet *packet);
bool packet_frag_mf(Packet *packet);
bool packet_frag_df(Packet *packet);
uint16_t packet_frag_offset(Packet *packet);
```

TCP, UDP, and SCTP ports:

```c
uint16_t packet_srcport(Packet *packet);
uint16_t packet_dstport(Packet *packet);
```

TCP fields:

```c
uint32_t packet_seq(Packet *packet);      /* Sequence */
uint32_t packet_ack(Packet *packet);      /* Acknowledgement */

uint16_t packet_mss(Packet *packet);
uint16_t packet_win(Packet *packet);
uint16_t packet_winscale(Packet *packet);

int packet_tcpflags(Packet *packet);
bool packet_tcp_fin(Packet *packet);
bool packet_tcp_syn(Packet *packet);
bool packet_tcp_rst(Packet *packet);
bool packet_tcp_push(Packet *packet);
bool packet_tcp_ack(Packet *packet);
bool packet_tcp_urg(Packet *packet);
```

Payload pseudo-protocol:

```c
void packet_set_payload(Packet *packet, void *payload, uint32_t paysize);
bool packet_has_alt_payload(Packet *packet);

uint32_t packet_raw_paysize(Packet *packet);
const uint8_t *packet_raw_payload(Packet *packet);

uint32_t packet_paysize(Packet *packet);
const uint8_t *packet_payload(Packet *packet);
```

The alternate payload pointer can be used to associate defragmented data with a
packet (see `extras/defragment.c`).

## Tests

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

## Documentation

- Man page: `doc/libpacket.md.1`
- Header files: `include/packet/packet.h`, `include/packet/ipaddr.h`,
  `include/packet/protocol.h`, `include/packet/options.h`,
  `include/packet/stats.h`

## Contributing

Issues and pull requests are welcome. If you are adding new protocol support,
please include tests that cover decode behavior and accessors.

## License

LibPacket is distributed under a BSD-style license. See the source headers for
license text.
