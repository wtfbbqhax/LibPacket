#include <gtest/gtest.h>
#include <packet/packet.h>

TEST(PacketCreateTest, PacketCreate)
{
    Packet *packet = packet_create();

    ASSERT_TRUE(packet != NULL);

    packet_destroy(packet);
}

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
