#ifndef __NG_ARP_H__
#define __NG_ARP_H__

#include <rte_ether.h>
#include <rte_malloc.h>


// ARP表 ARP规则定义
#define ARP_ENTRY_STATUS_DYNAMIC 0
#define ARP_ENTRY_STATUS_STATIC 1



// arp reply信息
uint8_t g_default_arp_mac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t g_default_eth_mac[RTE_ETHER_ADDR_LEN] = {0x00};


// ARP表数据结构
struct arp_entry 
{
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
    // 动态静态
    uint8_t type;
    // 内存没有对齐


    // 双向链表
    struct arp_entry *next;
    struct arp_entry *prev;
};

// ARP表
struct arp_table 
{
    struct arp_entry *entries;
    int count;
};

// 添加和删除
#define LL_ADD(item, list) do { \
    item ->prev = NULL; \
    item ->next =list; \
    if (list != NULL) list->prev = item;\
    list = item; \
} while (0)

#define LL_REMOVE(item, list) do { \
    if (item->prev != NULL) item->prev->next = item->next; \
    if (item->next != NULL) item->next->prev = item->prev; \
    if (list == item) list = item->next; \
    item->prev = item->next; \
} while(0) 

// 单例模式ARP
static struct arp_table *arpt = NULL;
static struct arp_table *arp_table_instance (void)
{
    if (arpt == NULL)
    {
        // name size 对齐
        arpt = (struct arp_table*)rte_malloc("arp_table", sizeof(struct arp_table), 0);
        if (arpt == NULL)
        {
            rte_exit(EXIT_FAILURE, "ARPTable Create Memory Error");
        }
        memset(arpt, 0, sizeof(struct arp_table));
    }

    return arpt;
}


// 获取目标MAC地址
static uint8_t* get_dst_mac(uint32_t dip)
{
    // ARP数据迭代器
    struct arp_entry *iter;
    // ARP数据表表头
    struct arp_table *table = arp_table_instance();

    // 遍历本地ARP解析表
    for (iter = table->entries; iter != NULL; iter = iter->next)
    {
        if (dip == iter->ip)
        {
            return iter->hwaddr;
        }
    }
    return NULL;
}
#endif