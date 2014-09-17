#include <packet_private.h>
#include <check.h>

#include "test.h"

START_TEST(test_packet_create)
{
    Packet *packet = packet_create( );

    fail_unless((packet != NULL), "packet_create returned NULL");

    packet_destroy(packet);
}
END_TEST

Suite * packet_create_suite(void)
{
    Suite *s = suite_create("Packet - Positive - packet create");
    TCase *tc = tcase_create("Positive");

    suite_add_tcase(s, tc);
    tcase_add_test(tc, test_packet_create);

    return s;
}

MAIN(packet_create_suite);
