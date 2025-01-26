# LibPacket

LibPacket is a portable TCP/IP packet decoding and parsing library designed to
provide a clean API for creating packet sniffers. It supports a wide range of
protocol headers and is compatible with multiple Unix-like operating systems.

## Features

 - Comprehensive Protocol Support: Decode various protocol headers, including:
   Ethernet, VLAN/802.1Q, IPv4, IPv6, MPLS, PPP, PPPOE, TCP, UDP, SCTP, ICMP,
   and ICMPv6. Experimental support is also available for IPX and SPX.

 - Cross-Platform Compatibility: Tested on Linux and MacOS.

 - Clean and Intuitive API: Designed to facilitate the development of packet
   sniffers with ease.

> [!NOTE]
> FreeBSD and OpenBSD are no longer tested for compatibility, please submit
> pull requests.

# Getting Started

Prerequisites
 * CMake
 * Docker (optional for contributors)
 * A compatible C compiler

# Installation

1.	Clone the Repository:

```
git clone https://github.com/wtfbbqhax/LibPacket.git libpacket
cd libpacket
```

2.	Build and Install:

```
make build
sudo make install
```

## Usage

To get started with LibPacket, include the relevant headers in your project:

```
#include <packet/packet.h>
#include <packet/ipaddr.h>
#include <packet/protocol.h>
#include <packet/options.h>
#include <packet/stats.h>
```

The primary interface allows you to create and decode packets:

```
Packet* packet = packet_create();
int result = packet_decode(packet, raw_data, raw_data_size);
if (result == 0) {
    // Successfully decoded the packet
    // Access packet details here
}
packet_destroy(packet);
```

For detailed API documentation, please refer to the header files located in the
`include/packet/` directory.

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for
improvements, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.

## Credits 

Victor Roemer (wtfbbqhax)


---

## API Documentation

> [!IMPORTANT]
> I've begun reviving this project in FY2024, major API changes are planned through FY2026.

### Packet type

```c
Packet*         packet_create( );
void            packet_destroy(Packet *);
```

Allocates and destroy a packet instance respectively.

```c
int packet_decode(Packet *packet, const unsigned char *raw_data, unsigned raw_data_size);
```

Decode's "raw\_data" and writes results into "packet".

### Protocol Layers

```c
Protocol*       packet_proto_first(Packet *packet, unsigned *);
Protocol*       packet_proto_next(Packet *packet, unsigned *);
unsigned        packet_proto_count(Packet *packet);

PROTOCOL        packet_proto_proto(Protocol *proto);
int             packet_proto_size(Protocol *proto);
const uint8_t*  packet_proto_data(Protocol *proto);
const char*     packet_proto_name(Protocol *proto);
```

### IPv4 and IPv6 Protocols

```c
int            packet_version(Packet *packet)

struct ipaddr  packet_srcaddr(Packet *packet)
struct ipaddr  packet_dstaddr(Packet *packet)

uint8_t        packet_protocol(Packet *packet)
uint32_t       packet_id(Packet *packet)
uint8_t        packet_ttl(Packet *packet)
uint8_t        packet_tos(Packet *packet)

bool           packet_is_fragment(Packet *packet)
bool           packet_frag_mf(Packet *packet)
bool           packet_frag_df(Packet *packet)
uint16_t       packet_frag_offset(Packet *packet)
```

### TCP, UDP and SCTP Protocols

The following are applicable to all transport protocols:

```
uint16_t       packet_srcport(Packet *packet)
uint16_t       packet_dstport(Packet *packet)
```

### TCP Protocol

The following methods return TCP specific decoded data.

```c
uint32_t       packet_seq(Packet *packet)      // Sequence #
uint32_t       packet_ack(Packet *packet)      // Acknowledgement #
uint16_t       packet_mss(Packet *packet)
uint16_t       packet_win(Packet *packet)
uint16_t       packet_winscale(Packet *packet)
int            packet_tcpflags(Packet *packet)
bool           packet_tcp_fin(Packet *packet)
bool           packet_tcp_syn(Packet *packet)
bool           packet_tcp_rst(Packet *packet)
bool           packet_tcp_push(Packet *packet)
bool           packet_tcp_ack(Packet *packet)
bool           packet_tcp_urg(Packet *packet)
```

### Payload Pseudo-Protocol

Payload is a pointer to the first octet, of the first unsupported protocol
encountered durring decoding phase. In many cases this will be application
data (e.g. the HTTP payload).

```c
void packet_set_payload(Packet *packet, void *payload, uint32_t paysize)
bool packet_has_alt_payload(Packet *packet)
```

Alternate payload pointer can be set by the user. This is currently only used
by the defragmentation engine which is found in `extras/defragment.c`. Defrag
support is builtin by default.


```c
uint32_t        packet_raw_paysize(Packet *packet);
const uint8_t*  packet_raw_payload(Packet *packet);
```

The raw payload refers to original wire bytes, never the alternate payload.


```c
uint32_t        packet_paysize(Packet *packet);
const uint8_t*  packet_payload(Packet *packet);
```

If `has_alt_payload`, the returned payload will point to Alternate payload
data, otherwise it will point to the original decode data.

