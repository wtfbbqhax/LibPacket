#include <packet_private.h>
#include <check.h>
#include "test.h"

#include <arpa/inet.h>

Packet *packet = NULL;

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

void setup( )
{
    packet = packet_create( );
    packet_decode(packet, pkt10, sizeof pkt10);
}

void teardown( )
{
    packet_destroy(packet);
}

/* Packet->version */
START_TEST(test_packet_version)
{
    fail_unless((packet_version(packet) == 4), "bad IP version");
}
END_TEST

/* Packet->srcaddr */
START_TEST(test_packet_srcaddr)
{
    char srcaddr[INET_ADDRSTRLEN];
    struct ipaddr saddr = packet_srcaddr(packet);
    inet_ntop(AF_INET, &saddr, srcaddr, INET_ADDRSTRLEN);
    fail_if(strcmp(srcaddr, "10.1.2.3"), "bad source address");
}
END_TEST

/* Packet->dstaddr */
START_TEST(test_packet_dstaddr)
{
    char dstaddr[INET_ADDRSTRLEN];
    struct ipaddr daddr = packet_dstaddr(packet);
    inet_ntop(AF_INET, &daddr, dstaddr, INET_ADDRSTRLEN);
    fail_if(strcmp(dstaddr, "10.9.8.7"), "bad destination address");
}
END_TEST

/* Packet->mf || Packet->offset */
START_TEST(test_packet_is_fragment)
{
    /* Just MF */
    packet->mf = true;
    fail_unless((packet_is_fragment(packet) == true),
        "packet_is_fragment returned false");

    packet->mf = false;
    fail_unless((packet_is_fragment(packet) == false),
        "packet_is_fragment returned true");

    /* Just OFF */
    packet->offset = 8*2;
    fail_unless((packet_is_fragment(packet) == true),
        "packet_is_fragment returned false");

    packet->offset = 0;
    fail_unless((packet_is_fragment(packet) == false),
        "packet_is_fragment returned true");

    /* Both */
    packet->offset = 8*2;
    packet->mf = true;
    fail_unless((packet_is_fragment(packet) == true),
        "packet_is_fragment returned false");

    packet->offset = 0;
    packet->mf = false;
    fail_unless((packet_is_fragment(packet) == false),
        "packet_is_fragment returned true");
}
END_TEST

/* Packet->mf */
START_TEST(test_packet_frag_mf)
{
    packet->mf = true;
    fail_unless((packet_frag_mf(packet) == true),
        "packet_frag_mf returned false");

    packet->mf = false;
    fail_unless((packet_frag_mf(packet) == false),
        "packet_frag_mf returned true");
}
END_TEST

/* Packet->df */
START_TEST(test_packet_frag_df)
{
    packet->df = true;
    fail_unless((packet_frag_df(packet) == true),
        "packet_frag_df returned false");

    packet->df = false;
    fail_unless((packet_frag_df(packet) == false),
        "packet_frag_df returned true");
}
END_TEST

/* Packet->offset */
START_TEST(test_packet_frag_offset)
{
    packet->offset = 8*2;
    fail_unless((packet_is_fragment(packet) == true),
        "packet_is_fragment returned false");

    packet->offset = 0;
    fail_unless((packet_is_fragment(packet) == false),
        "packet_is_fragment returned true");
}
END_TEST

/* Packet->protocol */
START_TEST(test_packet_protocol)
{
    fail_unless((packet_protocol(packet) == IPPROTO_TCP),
        "packet_proto did not return TCP");
}
END_TEST

/* Packet->id */
START_TEST(test_packet_id)
{
    fail_unless((packet_id(packet) == 1536),
        "packet_id did not return 1536");
}
END_TEST

/* Packet->ttl */
START_TEST(test_packet_ttl)
{
    fail_unless((packet_ttl(packet) == 64),
        "packet_ttl did not return 64");
}
END_TEST

/* Packet->tos */
START_TEST(test_packet_tos)
{
    fail_unless((packet_tos(packet) == 0),
        "packet_tos did not return 0");
}
END_TEST

/* Packet->srcport */
START_TEST(test_packet_srcport)
{
    fail_unless((packet_srcport(packet) == 48620),
        "packet_srcport did not return 48620");
}
END_TEST

/* Packet->dstport */
START_TEST(test_packet_dstport)
{
    fail_unless((packet_dstport(packet) == 8),
        "packet_dstport did not return 8");
}
END_TEST

/* Packet->mss */
START_TEST(test_packet_mss)
{
    /* XXX We don't populate this yet */
}
END_TEST

/* Packet->win */
START_TEST(test_packet_win)
{
}
END_TEST

/* Packet->winscale */
START_TEST(test_packet_winscale)
{
    /* XXX We don't populate this yet */
}
END_TEST

/* Packet->seq */
START_TEST(test_packet_seq)
{
    fail_unless((packet_seq(packet) == 452),
        "packet_seq did not return 452");
}
END_TEST

/* Packet->ack */
START_TEST(test_packet_ack)
{
    fail_unless((packet_ack(packet) == 2),
        "packet_ack did not return 2");
}
END_TEST

/* Packet->flags & fin */
START_TEST(test_packet_tcp_fin)
{
    fail_unless((packet_tcp_fin(packet) == false),
        "packet_tcp_fin returned true");
}
END_TEST

/* Packet->flags & syn */
START_TEST(test_packet_tcp_syn)
{
    fail_unless((packet_tcp_syn(packet) == false),
        "packet_tcp_syn returned true");
}
END_TEST

/* Packet->flags & rst */
START_TEST(test_packet_tcp_rst)
{
    fail_unless((packet_tcp_rst(packet) == false),
        "packet_tcp_rst returned true");
}
END_TEST

/* Packet->flags & push */
START_TEST(test_packet_tcp_push)
{
    fail_unless((packet_tcp_push(packet) == true),
        "packet_tcp_push returned false");
}
END_TEST

/* Packet->flags & ack */
START_TEST(test_packet_tcp_ack)
{
    fail_unless((packet_tcp_ack(packet) == true),
        "packet_tcp_push returned false");
}
END_TEST

/* Packet->flags & urg */
START_TEST(test_packet_tcp_urg)
{
    fail_unless((packet_tcp_urg(packet) == false),
        "packet_tcp_urg returned true");
}
END_TEST

/* Packet->payload */
START_TEST(test_packet_payload)
{
    fail_unless((packet_payload(packet) != NULL),
        "packet_payload returned NULL");
}
END_TEST

/* Packet->paysize */
START_TEST(test_packet_paysize)
{
    fail_unless(packet_paysize(packet),
        "packet_paysize returned 0");
}
END_TEST

Suite * packet_accessors_suite(void)
{
    Suite *s = suite_create("Packet Accessor Functions");
    TCase *tc = tcase_create("Core");
    tcase_add_checked_fixture(tc, setup, teardown);

    suite_add_tcase(s, tc);
    tcase_add_test(tc, test_packet_version);
    tcase_add_test(tc, test_packet_srcaddr);
    tcase_add_test(tc, test_packet_dstaddr);
    tcase_add_test(tc, test_packet_is_fragment);
    tcase_add_test(tc, test_packet_frag_mf);
    tcase_add_test(tc, test_packet_frag_df);
    tcase_add_test(tc, test_packet_frag_offset);
    tcase_add_test(tc, test_packet_protocol);
    tcase_add_test(tc, test_packet_id);
    tcase_add_test(tc, test_packet_ttl);
    tcase_add_test(tc, test_packet_tos);
    tcase_add_test(tc, test_packet_srcport);
    tcase_add_test(tc, test_packet_dstport);
    tcase_add_test(tc, test_packet_mss);
    tcase_add_test(tc, test_packet_win);
    tcase_add_test(tc, test_packet_winscale);
    tcase_add_test(tc, test_packet_seq);
    tcase_add_test(tc, test_packet_ack);
    tcase_add_test(tc, test_packet_tcp_fin);
    tcase_add_test(tc, test_packet_tcp_syn);
    tcase_add_test(tc, test_packet_tcp_rst);
    tcase_add_test(tc, test_packet_tcp_push);
    tcase_add_test(tc, test_packet_tcp_ack);
    tcase_add_test(tc, test_packet_tcp_urg);
    tcase_add_test(tc, test_packet_payload);
    tcase_add_test(tc, test_packet_paysize);

    return s;
}

MAIN(packet_accessors_suite);
