#include <arpa/inet.h>
#include <cstring>

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

const char* alt_payload = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

TEST(PacketAltPayloadTest, AlternatePayloadSize)
{
    Packet* packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));
    packet_set_payload(packet, (uint8_t*)alt_payload, strlen(alt_payload));

    int len1 = packet_paysize(packet);
    int len2 = strlen(alt_payload);
    ASSERT_EQ(len1, len2) << "Alternate payload size is wrong";

    packet_set_payload(packet, NULL, 0);
    packet_destroy(packet);
}

TEST(PacketAltPayloadTest, AlternatePayload)
{
    Packet* packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));
    packet_set_payload(packet, (uint8_t*)alt_payload, strlen(alt_payload));

    const uint8_t* pay = packet_payload(packet);
    int paysize = strlen((char*)pay);

    ASSERT_EQ(memcmp(pay, (const uint8_t*)alt_payload, paysize), 0)
        << "Alternate payload is wrong";

    packet_set_payload(packet, NULL, 0);
    packet_destroy(packet);
}

TEST(PacketAltPayloadTest, HasAlternatePayload)
{
    Packet* packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));
    packet_set_payload(packet, (uint8_t*)alt_payload, strlen(alt_payload));

    ASSERT_TRUE(packet_has_alt_payload(packet))
        << "Packet claims to have no alternate payload";

    packet_set_payload(packet, NULL, 0);
    packet_destroy(packet);
}

TEST(PacketAltPayloadTest, RawPayload)
{
    Packet* packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));
    packet_set_payload(packet, (uint8_t*)alt_payload, strlen(alt_payload));

    const uint8_t* raw = packet_raw_payload(packet);
    const uint8_t* alt = packet_payload(packet);
    ASSERT_NE(raw, alt) << "Packet raw payload is incorrect";

    packet_set_payload(packet, NULL, 0);
    packet_destroy(packet);
}

TEST(PacketAltPayloadTest, RawPayloadSize)
{
    Packet* packet = packet_create();
    packet_decode(packet, pkt10, sizeof(pkt10));
    packet_set_payload(packet, (uint8_t*)alt_payload, strlen(alt_payload));

    const uint32_t raw = packet_raw_paysize(packet);
    const uint32_t alt = packet_paysize(packet);
    ASSERT_NE(raw, alt) << "Packet raw payload size is incorrect";

    packet_set_payload(packet, NULL, 0);
    packet_destroy(packet);
}

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
