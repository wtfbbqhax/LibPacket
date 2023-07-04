              _ _ _                      _        _
             | (_) |__  _ __   __ _  ___| | _____| |_
             | | | '_ \| '_ \ / _` |/ __| |/ / _ \ __|
             | | | |_) | |_) | (_| | (__|   <  __/ |_
             |_|_|_.__/| .__/ \__,_|\___|_|\_\___|\__|
                       |_|

Release: 0.2.0
Bug Report: github.com/wtfbbqhax/LibPacket/issues

TCP/IP packet decoder/parser that provides a clean API to aide in the
creation of packet sniffers.


Platforms
---------


Expected to work on the following OSs:
 - Linux
 - Mac OSX
 - FreeBSD
 - OpenBSD

* If it doesn't work on the listed platforms, or you would like it to
 work on a different platform; please submit an issue.


Protocol Support
----------------

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

Experimental support is provided for the following protocol headers:
 - IPX
 - SPX


Build and Install
-----------------

```sh
cmake -B build -G Ninja .
cmake --build build
sudo cmake --install build
```

Getting Started
---------------


Refer to the header files:
 - include/packet/packet.h
 - include/packet/ipaddr.h
 - include/packet/protocol.h
 - include/packet/options.h
 - include/packet/stats.h

The primary interface is documented below:

## Packet type

|    Packet*         packet_create( );
|    void            packet_destroy(Packet *);

Allocates and destroy a packet instance respectively.


|    int             packet_decode(Packet *packet, const unsigned char *raw_data, unsigned raw_data_size);

Decode's "raw_data" and writes results into "packet".

## Protocol Layers

|    Protocol*       packet_proto_first(Packet *packet, unsigned *);
|    Protocol*       packet_proto_next(Packet *packet, unsigned *);
|    unsigned        packet_proto_count(Packet *packet);
|
|    PROTOCOL        packet_proto_proto(Protocol *proto);
|    int             packet_proto_size(Protocol *proto);
|    const uint8_t*  packet_proto_data(Protocol *proto);
|    const char*     packet_proto_name(Protocol *proto);


## IPv4 and IPv6 Protocols

|    int            packet_version(Packet *packet)
|
|    struct ipaddr  packet_srcaddr(Packet *packet)
|    struct ipaddr  packet_dstaddr(Packet *packet)
|
|    uint8_t        packet_protocol(Packet *packet)
|    uint32_t       packet_id(Packet *packet)
|    uint8_t        packet_ttl(Packet *packet)
|    uint8_t        packet_tos(Packet *packet)
|
|    bool           packet_is_fragment(Packet *packet)
|    bool           packet_frag_mf(Packet *packet)
|    bool           packet_frag_df(Packet *packet)
|    uint16_t       packet_frag_offset(Packet *packet)


## TCP, UDP and SCTP Protocols

|    uint16_t       packet_srcport(Packet *packet)
|    uint16_t       packet_dstport(Packet *packet)


## TCP Protocol

|    uint32_t       packet_seq(Packet *packet)      // Sequence #
|    uint32_t       packet_ack(Packet *packet)      // Acknowledgement #
|
|    uint16_t       packet_mss(Packet *packet)
|    uint16_t       packet_win(Packet *packet)
|    uint16_t       packet_winscale(Packet *packet)
|
|    int            packet_tcpflags(Packet *packet)
|    bool           packet_tcp_fin(Packet *packet)
|    bool           packet_tcp_syn(Packet *packet)
|    bool           packet_tcp_rst(Packet *packet)
|    bool           packet_tcp_push(Packet *packet)
|    bool           packet_tcp_ack(Packet *packet)
|    bool           packet_tcp_urg(Packet *packet)


# Payload Pseudo-Protocol

Paylaod is a pointer to the start of the first un-supported protocol encountered
durring decoding phase; normally the "Application Protocol" (e.g. HTTP).

|    void    packet_set_payload(Packet *packet, void *payload, uint32_t paysize);
|    bool    packet_has_alt_payload(Packet *packet);

Set the "alternate payload" pointer to "payload".
Used to associate defragmented data to a packet (see "extras/defragment.c").


|    uint32_t        packet_raw_paysize(Packet *packet);
|    const uint8_t*  packet_raw_payload(Packet *packet);

The "raw" payload is returned always.


|    uint32_t        packet_paysize(Packet *packet);
|    const uint8_t*  packet_payload(Packet *packet);

Returns the "alt" payload if set; the "raw" payload otherwise.

