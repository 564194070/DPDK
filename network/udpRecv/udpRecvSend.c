#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>


#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>


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



// 数据包发送五元组构建
static uint16_t g_src_port;
static uint16_t g_dst_port;


static uint32_t g_src_ip;
static uint32_t g_dst_ip;

static uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
static uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];





// 初始化网卡
static void ifIndex_init (struct rte_mempool * mbuf_pool)
{
    // 检查可用网卡数量
    // 1.检测端口是否合法
    // 绑定了多少个网卡绑定了PCIE IGB VFIO啥的
    // 获取默认网卡信息，还没有添加DPDK信息
    uint16_t ifIndex_ports = rte_eth_dev_count_avail();
    if (ifIndex_ports == 0)
    {
        rte_exit(EXIT_FAILURE, "Select Eth Not Ready\n");
    }

    // 获取网卡基本信息
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(g_dpdk_ifIndex, &dev_info);

    // 2.添加DPDK基本信息
    // 设置发送接收队列
    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf ifIndex_config = ifIndex_conf_default;
    rte_eth_dev_configure(g_dpdk_ifIndex, num_rx_queues, num_tx_queues, &ifIndex_config);

    // 设置网卡
    int ret;
    // 配置接收队列
    ret = rte_eth_rx_queue_setup(g_dpdk_ifIndex, 0, 128, rte_eth_dev_socket_id(g_dpdk_ifIndex), NULL, mbuf_pool);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Setup Rx Queue Error\n");
    }
    // 配置发送队列
    ret = -1;
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    // tx队列的负载，接受和发送同步
    txq_conf.offloads = ifIndex_config.rxmode.offloads;
    // 网口，队列，队列最大包负载，socketid，配置信息
    // 512 < n < 4096
    ret = rte_eth_tx_queue_setup(g_dpdk_ifIndex, 0, 1024, rte_eth_dev_socket_id(g_dpdk_ifIndex),&txq_conf);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Setup Tx Queue Error\n");
    }




    // 启动网卡
    ret = -1;
    ret = rte_eth_dev_start(g_dpdk_ifIndex);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Start Eth Error\n");
    }

    // 读取MAC地址
    //struct ether_addr addr_mac;
    //rte_eth_macaddr_get(g_dpdk_ifIndex, &addr_mac);

    //开启网卡混杂模式
    //rte_eth_promiscuous_get(g_dpdk_ifIndex);


}   


// UDP数据包构建
// msg，需要发送的数据，数据的长度
static int build_udp_packet(uint8_t *msg, unsigned char* data, uint16_t total_len)
{
    // 主要作用 打包成一个UDP的数据包
    // 构建以太网头
    // 两个字节以上，都转换
    struct rte_ether_hdr *ethhdr = (struct rte_ether_hdr*)msg;
    // 源IP地址
    rte_memcpy(ethhdr->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
    // 目的IP地址
    rte_memcpy(ethhdr->d_addr.addr_bytes, g_dst_mac, RTE_ETHER_ADDR_LEN);
    ethhdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);


    // 构建IP头
    struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    // 4位版本，4位包长度
    iphdr->version_ihl = 0x45;
    // IP里面的类型 TOS服务类型
    iphdr->type_of_service = 0;
    // 数据包总长度
    iphdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    // 16位标识
    iphdr->packet_id = 0;
    // 偏移量
    iphdr->fragment_offset = 0;
    // 最大生存时间TTL
    iphdr->time_to_live = 64;
    // 8位IP协议
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->src_addr = g_src_ip;
    iphdr->dst_addr = g_dst_ip;
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    // 构建UDP头
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr*)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udphdr->src_port = g_src_port;
    udphdr->dst_port = g_dst_port;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udphdr->dgram_len = htons(udplen);

    // 将数据拷贝到数据区
    // 指针跳过UDP头
    rte_memcpy((uint8_t*)(udphdr+1),data,udplen);
    udphdr->dgram_cksum = 0;
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr,udphdr);

    struct in_addr addr;
	addr.s_addr = g_src_ip;
	printf(" --> src: %s:%d\n", inet_ntoa(addr), ntohs(g_src_port));

	addr.s_addr = g_dst_ip;
	printf(" --> dst: %s:%d\n", inet_ntoa(addr), ntohs(g_dst_port));

	return 0;


}

// 发送数据
// 内存池，数据，长度
static struct rte_mbuf* send_udp_pack(struct rte_mempool *mbuf_pool, uint8_t* data, uint16_t length)
{
    //mempool -> mbuf
    // 主要作用
    // 从内存池中获取了mbuf

    // DPDK所有的内存都是从内存池获取的，每次都是在内存池拿取。
    // 每次最小的一个单位就是mbuf

    // 14Byte以太网头，20字节IP头，8字节UDP头 应用数据
    // 14 + 20 + 8 =42
    const unsigned total_len = length + 42;
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf)
    {
        rte_exit(EXIT_FAILURE, "Error with sendUDP Queue");
    }

    // 为了DPDK数据协议的处理
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    // 拿到内存池中mbuf指针，指向的具体位置
    uint8_t* pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
    // 拿出了我们的使用位置，然后对这个地方的内存进行处理

    build_udp_packet(pktdata, data, total_len);
    return mbuf;
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
    rte_eth_macaddr_get(g_dpdk_ifIndex,(struct rte_ether_addr* )g_src_mac);

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


                // 获取发送端数据               uint16_t udpPort = 5641;

                rte_memcpy(g_dst_mac, ethhdr->s_addr.addr_bytes,RTE_ETHER_ADDR_LEN);
                rte_memcpy(&g_src_ip, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&g_dst_ip, &iphdr->src_addr, sizeof(uint32_t));
                rte_memcpy(&g_src_port, &udphdr->dst_port, sizeof(uint16_t));
                rte_memcpy(&g_dst_port, &udphdr->src_port, sizeof(uint16_t));



                uint16_t length = ntohs(udphdr->dgram_len);
                *((char*)udphdr + length) = '\0';

                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src :%s:%d\n",inet_ntoa(addr),  ntohs(udphdr->src_port));
                addr.s_addr = iphdr->dst_addr;
                printf("dst :%s:%d\n",inet_ntoa(addr),  ntohs(udphdr->dst_port));
                printf ("message :%s\n",(char *)(udphdr + 1));


                struct rte_mbuf *txbuf = send_udp_pack(mbuf_pool,(uint8_t *)(udphdr + 1), length);
                // 从某个网卡，某个队列，发送某个内存，发送一个包
                rte_eth_tx_burst(g_dpdk_ifIndex,0,&txbuf,1);
                rte_pktmbuf_free(txbuf);


                // 释放内存
                rte_pktmbuf_free(mbufs[index]);
            }

        }

    }
    
}
