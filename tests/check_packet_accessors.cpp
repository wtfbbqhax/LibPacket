#include <arpa/inet.h>

#include <gtest/gtest.h>
#include <packet/packet.h>

const uint8_t pkt10[] = {
    0x02, 0x09, 0x08, 0x07, 0x06, 0x05, 0x02, 0x01, 0x02, 0x03, 
    0x04, 0x05, 0x88, 0x64, 0x00, 0x00, 0x00, 0x02, 0x00, 0xC0, 
    0x00, 0x21, 0x45, 0x00, 0x00, 0xBE, 0x00, 0x06, 0x00, 0x00, 
    0x40, 0x06, 0x5C, 0x21, 0x0A, 0x01, 0x02, 0x03, 0x0A, 0x09, 
    0x08, 0x07, 0xBD, 0xEC, 0x00, 0x08, 0x00, 0x00, 0x01, 0xC4, 
    0x00, 0x00, 0x00, 0x02, 0x50, 0x18, 0x01, 0x00, 0xC8, 0xB2, 
    0x00, 0x00, 0x6C, 0x2C, 0x20, 0x77, 0x65, 0x20, 0x64, 0x69, 
    0x64, 0x20, 0x64, 0x6F, 0x20, 0x74, 0x68, 0x65, 0x20, 0x68, 
    0x65, 0x61, 0x64, 0x65, 0x72, 0x2E, 0x0A, 0x47, 0x4F, 0x52, 
    0x45, 0x3A, 0x20, 0x54, 0x68, 0x65, 0x20, 0x68, 0x65, 0x61, 
    0x64, 0x65, 0x72, 0x3F, 0x0A, 0x42, 0x49, 0x44, 0x45, 0x4E, 
    0x3A, 0x20, 0x41, 0x6E, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 
    0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72, 0x20, 0x2D, 0x2D, 
    0x20, 0x62, 0x75, 0x74, 0x20, 0x73, 0x68, 0x65, 0x20, 0x69, 
    0x73, 0x20, 0x61, 0x20, 0x70, 0x61, 0x63, 0x6B, 0x65, 0x74, 
    0x21, 0x0A, 0x43, 0x52, 0x4F, 0x57, 0x44, 0x3A, 0x20, 0x52, 
    0x6F, 0x75, 0x74, 0x65, 0x20, 0x68, 0x65, 0x72, 0x21, 0x20, 
    0x20, 0x50, 0x61, 0x63, 0x6B, 0x65, 0x74, 0x21, 0x20, 0x20, 
    0x50, 0x61, 0x63, 0x6B, 0x65, 0x74, 0x21, 0x20, 0x20, 0x52, 
    0x6F, 0x75, 0x74, 0x65, 0x20, 0x68, 0x65, 0x72, 0x21, 0x0A, 
    0x47, 0x4F, 0x52, 0x45, 0x3A, 0x20, 0x44, 0x69, 0x64, 0x20, 
    0x79, 0x6F
};

void teardown()
{
}

TEST(PacketAccessorsTest, PacketVersion)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    ASSERT_EQ(packet_version(packet), 4) << "bad IP version";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketSrcAddr)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    char srcaddr[INET_ADDRSTRLEN];
    struct ipaddr saddr = packet_srcaddr(packet);
    inet_ntop(AF_INET, &saddr, srcaddr, INET_ADDRSTRLEN);
    ASSERT_STREQ(srcaddr, "10.1.2.3") << "bad source address";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketDstAddr)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

     char dstaddr[INET_ADDRSTRLEN];
    struct ipaddr daddr = packet_dstaddr(packet);
    inet_ntop(AF_INET, &daddr, dstaddr, INET_ADDRSTRLEN);
    ASSERT_STREQ(dstaddr, "10.9.8.7") << "bad destination address";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketIsFragment)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    // Just MF
    packet->mf = true;
    ASSERT_TRUE(packet_is_fragment(packet)) << "packet_is_fragment returned false";

    packet->mf = false;
    ASSERT_FALSE(packet_is_fragment(packet)) << "packet_is_fragment returned true";

    // Just OFF
    packet->offset = 8 * 2;
    ASSERT_TRUE(packet_is_fragment(packet)) << "packet_is_fragment returned false";

    packet->offset = 0;
    ASSERT_FALSE(packet_is_fragment(packet)) << "packet_is_fragment returned true";

    // Both
    packet->offset = 8 * 2;
    packet->mf = true;
    ASSERT_TRUE(packet_is_fragment(packet)) << "packet_is_fragment returned false";

    packet->offset = 0;
    packet->mf = false;
    ASSERT_FALSE(packet_is_fragment(packet)) << "packet_is_fragment returned true";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketFragMf)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    packet->mf = true;
    ASSERT_TRUE(packet_frag_mf(packet)) << "packet_frag_mf returned false";

    packet->mf = false;
    ASSERT_FALSE(packet_frag_mf(packet)) << "packet_frag_mf returned true";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketFragDf)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    packet->df = true;
    ASSERT_TRUE(packet_frag_df(packet)) << "packet_frag_df returned false";

    packet->df = false;
    ASSERT_FALSE(packet_frag_df(packet)) << "packet_frag_df returned true";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketFragOffset)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    packet->offset = 8 * 2;
    ASSERT_TRUE(packet_is_fragment(packet)) << "packet_is_fragment returned false";

    packet->offset = 0;
    ASSERT_FALSE(packet_is_fragment(packet)) << "packet_is_fragment returned true";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketProtocol)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    ASSERT_EQ(packet_protocol(packet), IPPROTO_TCP) << "packet_proto did not return TCP";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketId)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    ASSERT_EQ(packet_id(packet), 1536) << "packet_id did not return 1536";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketTtl)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_EQ(packet_ttl(packet), 64) << "packet_ttl did not return 64";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketTos)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_EQ(packet_tos(packet), 0) << "packet_tos did not return 0";
}

TEST(PacketAccessorsTest, PacketSrcPort)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_EQ(packet_srcport(packet), 48620) << "packet_srcport did not return 48620";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketDstPort)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_EQ(packet_dstport(packet), 8) << "packet_dstport did not return 8";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketMss)
{
    // XXX We don't populate this yet
}

TEST(PacketAccessorsTest, PacketWin)
{
    // implementation
}

TEST(PacketAccessorsTest, PacketWinscale)
{
    // XXX We don't populate this yet
}

TEST(PacketAccessorsTest, PacketSeq)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_EQ(packet_seq(packet), 452) << "packet_seq did not return 452";
}

TEST(PacketAccessorsTest, PacketAck)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_EQ(packet_ack(packet), 2) << "packet_ack did not return 2";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketTcpFin)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_FALSE(packet_tcp_fin(packet)) << "packet_tcp_fin returned true";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketTcpSyn)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_FALSE(packet_tcp_syn(packet)) << "packet_tcp_syn returned true";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketTcpRst)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_FALSE(packet_tcp_rst(packet)) << "packet_tcp_rst returned true";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketTcpPush)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_TRUE(packet_tcp_push(packet)) << "packet_tcp_push returned false";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketTcpAck)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_TRUE(packet_tcp_ack(packet)) << "packet_tcp_push returned false";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketTcpUrg)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_FALSE(packet_tcp_urg(packet)) << "packet_tcp_urg returned true";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketPayload)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));


    ASSERT_TRUE(packet_payload(packet) != NULL) << "packet_payload returned NULL";

    packet_destroy(packet);
}

TEST(PacketAccessorsTest, PacketPaySize)
{
    Packet * packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));

    ASSERT_TRUE(packet_paysize(packet)) << "packet_paysize returned 0";

    packet_destroy(packet);
}

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
