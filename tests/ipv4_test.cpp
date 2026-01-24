#include <gtest/gtest.h>
#include "ipv4.h"

struct ipv4_header header2 = {
  .version_ihl = 2
};

TEST(IPV4TEST, HeaderVersion2){
    EXPECT_EQ(2, header2.version_ihl);
  }