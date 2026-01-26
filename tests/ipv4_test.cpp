#include <gtest/gtest.h>
#include "ipv4.h"

struct ipv4_header_t header2 = {
    .version_ihl = 2,
};

TEST(IPV4TEST, HeaderVersion2) { EXPECT_EQ(2, header2.version_ihl); }

TEST(IPV4TEST, CheckSumTest)
{
    EXPECT_NE(0, calc_header_checksum(&header2, sizeof(struct ipv4_header_t)));
}