#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>


#include <stdio.h>
#include <arpa/inet.h>


// 内存池中的块 4K - 1
#define NUMMBUFS (4096 - 1)
// 定义缓冲区最多接受的报文数量
#define BURSTSIZE 32
// 定义网卡ID
int g_dpdk_ifIndex = 0;

// 默认配置 项目使用点运算符和成员名
static const struct rte_eth_conf ifIndex_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

// 初始化网卡
static void ifIndex_init (struct rte_mempool * mbuf_pool)
{
    // 检查可用网卡数量
    uint16_t ifIndex_ports = rte_eth_dev_count_avail();
    if (ifIndex_ports == 0)
    {
        rte_exit(EXIT_FAILURE, "Select Eth Not Ready\n");
    }

    // 获取网卡基本信息
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(g_dpdk_ifIndex, &dev_info);

    // DPDK配置网卡
    // 设置发送接收队列
    const int num_rx_queues = 1;
    const int num_tx_queues = 0;
    struct rte_eth_conf ifIndex_config = ifIndex_conf_default;
    rte_eth_dev_configure(g_dpdk_ifIndex, num_rx_queues, num_tx_queues, &ifIndex_config);

    // 设置网卡
    int ret;
    ret = rte_eth_rx_queue_setup(g_dpdk_ifIndex, 0, 128, rte_eth_dev_socket_id(g_dpdk_ifIndex), NULL, mbuf_pool);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Setup Rx Queue Error\n");
    }

    // 启动网卡
    ret = -1;
    ret = rte_eth_dev_start(g_dpdk_ifIndex);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Start Eth Error\n");
    }


}   

// 程序入口
int main(int argc, char* argv[])
{
    // 初始化DPDK配置
    int res = -1;
    res = rte_eal_init(argc, argv);
    if (res < 0)
    {
        rte_exit(EXIT_FAILURE, "Init DPDK Failed\n");
    }

    // 创建内存池 存储rte_mbuf 数据包缓存
    /*
        1. 名称 对象标识
        2. 对象中rte_mbuf结构体数量
        3. 是否开启CPU缓存
        4. 私有将数据大小
        5. mbuf数据区大小 headroom + 数据 2048+128/8192+128
        6. 对象所在NUMA的CPU的ID，创建内存池的位置
    */
    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUMMBUFS,0,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());
    if (mbuf_pool == NULL)
    {
        rte_exit(EXIT_FAILURE, "Could Not Create Buffer\n");
    }


    // 初始化网卡,启动DPDK
    ifIndex_init(mbuf_pool);

    // 网络收发流程
    while (1)
    {
        // 从缓冲区数据区域
        struct rte_mbuf *mbufs[BURSTSIZE];
        //                                    m->buf_len                m->pkt.data_len = m->pkt.pkt_len
        // rte_mbuf                           headroom                  data                                                                     tailroom
        //                                    m->buf_addr               m->pkt.data

        // 从缓冲区接受数据包，最多BURSTSIZE个数
        unsigned int num_recv_packs = rte_eth_rx_burst(g_dpdk_ifIndex, 0, mbufs, BURSTSIZE);
        if (num_recv_packs > BURSTSIZE)
        {
            rte_exit(EXIT_FAILURE, "Get Lots Of Data from Pool\n");
        }

        // 循环处理所有的数据包
        for (unsigned int index = 0; index < num_recv_packs; index ++)
        {
            // 以太网头
            struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(mbufs[index], struct rte_ether_hdr*);
            // 判别非IPV4数据包，不做处理
            if (ethhdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
            {
                continue;
            }
            //buf_addr     data_off         useroff
            struct rte_ipv4_hdr* iphdr = rte_pktmbuf_mtod_offset(mbufs[index],struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
            if (iphdr->next_proto_id == IPPROTO_UDP)
            {
                // 获取IP头 偏移量1=越过整个ip头，就指向了udp头
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr*)(iphdr + 1);

                uint16_t length = ntohs(udphdr->dgram_len);
                *((char*)udphdr + length) = '\0';

                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src :%s:%d\n",inet_ntoa(addr), udphdr->src_port);
                addr.s_addr = iphdr->dst_addr;
                printf("src :%s:%d\n",inet_ntoa(addr), udphdr->dst_port);
                printf ("message :%s\n",(char *)(udphdr + 1));

                // 释放内存
                rte_pktmbuf_free(mbufs[index]);
            }

        }

    }
    
}