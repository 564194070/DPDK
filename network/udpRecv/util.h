
#include <rte_ethdev.h>

// 打印MAC地址
static inline void print_mac(const char* what, const struct rte_ether_addr* eth_addr)
{
    // what 固定输出在屏幕上的内容, 
    // MAC地址 (struct rte_ether_addr*) uint8
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf,RTE_ETHER_ADDR_FMT_SIZE,eth_addr);
    printf("%s%s",what,buf);
}