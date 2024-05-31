#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_icmp.h>
#include <rte_timer.h>

#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>


#include <rte_malloc.h>

#include "arp.h"
#include "util.h"
#include "ring.h"

// 10ms*10000*12 一分钟
#define TIMER_RESOLUTION_CYCLES 20000000000ULL
#define TIME_RESOLUTION_CYCLES 20000000000ULL


// 计算IP的宏定义
#define MAKE_IPVE_ADDR(a,b,c,d)(a + (b<<8) + (c<<16) + (d<<24))


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



// 数据包五元组基础信息
static uint16_t g_src_port;
static uint16_t g_dst_port;


static uint32_t g_src_ip;
static uint32_t g_dst_ip;

static uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
static uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];



// UDP接受的广播信息IP变成广播地址，为了避免ARP受影响，从新生成变量
// static uint32_t g_src_arp_ip = MAKE_IPVE_ADDR(192,168,18,102);
// 172.20.4.33
static uint32_t g_src_arp_ip = MAKE_IPVE_ADDR(172,20,4,33);



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

    //struct in_addr addr;
	//addr.s_addr = g_src_ip;
	//printf(" --> src: %s:%d\n", inet_ntoa(addr), ntohs(g_src_port));

	//addr.s_addr = g_dst_ip;
	//printf(" --> dst: %s:%d\n", inet_ntoa(addr), ntohs(g_dst_port));

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



static int build_arp_packet(uint8_t *msg,uint16_t opcode, uint8_t* dst_mac, uint32_t src_ip, uint32_t dst_ip)
{
    // 以太网头
    struct rte_ether_hdr *ethhdr = (struct rte_ether_hdr*)msg;
    // 源IP地址
    rte_memcpy(ethhdr->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);

    // 目的IP地址
    if (strncmp ((const char*)dst_mac, (const char*)g_default_arp_mac, RTE_ETHER_ADDR_LEN))
    {
        // 每一位都是1,代表是没有ARP地址的信息
        rte_memcpy(ethhdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    }
    else
    {
        uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
        rte_memcpy(ethhdr->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
    }
    

    ethhdr->ether_type = htons(RTE_ETHER_TYPE_ARP);


    // ARP包
    struct rte_arp_hdr *arp = (struct rte_arp_hdr*)(ethhdr + 1);
    // 硬件 字节序转换
    arp->arp_hardware = htons(1);
    // 协议类型
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    // 硬件地址长度
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    // 软件地址长度
    arp->arp_plen = sizeof(uint32_t);
    // 软件操作长度 (请求1和返回2)
    arp->arp_opcode = htons(opcode);

    // 源IP地址
    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, g_src_mac,RTE_ETHER_ADDR_LEN);
    // 目的IP地址
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac,RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_sip = src_ip;
    arp->arp_data.arp_tip = dst_ip;
    return 0;
}


// ARP本身的功能，接受和发送
// ARP发起ARP查询,ARP发送ARP响应
static struct rte_mbuf* send_arp_pack(struct rte_mempool* mbuf_pool,uint16_t opcode , uint8_t* dst_mac, uint32_t src_ip, uint32_t dst_ip)
{
    // 14字节以太网
    // 28字节ARP

    const int total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    // 从内存池分配一个buf存储ARP数据包
    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf)
    {
        rte_exit(EXIT_FAILURE, "ARP Create Packet Error");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;
    uint8_t* pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
    build_arp_packet(pkt_data,opcode,dst_mac,src_ip,dst_ip);
    return mbuf;
}



static uint16_t ng_checksum(uint16_t *addr, int count) {

	register long sum = 0;

	while (count > 1) {

		sum += *(unsigned short*)addr++;
		count -= 2;
	
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

static int build_icmp_packet(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

	// 1 ether
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2 ip
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 icmp 
	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	// 类型 
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;

    // ICMP差错报文的类型
	icmp->icmp_code = 0;
    // 标识符
	icmp->icmp_ident = id;
    // 序列号
	icmp->icmp_seq_nb = seqnb;

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ng_checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));

	return 0;
}


static struct rte_mbuf *send_icmp_pack(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}

	
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	build_icmp_packet(pkt_data, dst_mac, sip, dip, id, seqnb);

	return mbuf;
}

// 定时器
// 定时器回调 参数定时器和需要回调的参数
static void arp_request_timer_cb (__attribute__((unused)) struct rte_timer* tim, __attribute__((unused)) void* arg)
{
    struct rte_mempool* mbuf_pool = (struct rte_mempool*)arg;
    struct inout_ring* ring = ringInstance();


    // 
    // rte_eth_tx_burst(g_dpdk_ifIndex,0,&arpbuf,1);
    // rte_pktmbuf_free(arpbuf);

    for (int index = 1; index < 254; ++index)
    {
        struct rte_mbuf* arpbuf = NULL ;


        uint32_t dstip = (g_src_arp_ip & 0x00FFFFFF) | (0xFF000000 & (index << 24));
        //struct in_addr addr;
        //addr.s_addr = dstip;
        //printf(" --> arp send: %s\n", inet_ntoa(addr));
        //addr.s_addr = g_src_arp_ip;
        //printf(" --> arp src send: %s\n", inet_ntoa(addr));
        uint8_t* dstmac =  get_dst_mac(dstip);
        if (dstmac == NULL)
        {
            // ARP表找不到内容，就发这样
            // arphdr -> mac :  FF:FF:FF:FF:FF:FF
            // ether -> mac:    00:00:00:00:00:00
            arpbuf = send_arp_pack(mbuf_pool, RTE_ARP_OP_REQUEST,g_default_arp_mac ,g_src_arp_ip,dstip);
        }
        else
        {
            // 能找到ARP信息
            arpbuf = send_arp_pack(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac ,g_src_arp_ip,dstip);
        }
        /*
        rte_eth_tx_burst(g_dpdk_ifIndex,0,&arpbuf,1);
        rte_pktmbuf_free(arpbuf);
        */
       rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
    }


}




// 处理逻辑的工作线程
static int pkt_process(void *arg);




// 172.20.4.33
// 192.168.18.155
// 11000000 10101000 00010010 10011011



int main(int argc, char* argv[])
{
    // 初始化DPDK配置
    int res = -1;
    res = rte_eal_init(argc, argv);
    if (res < 0)
    {
        rte_exit(EXIT_FAILURE, "Init DPDK Failed\n");
    }


    // 初始化内存池
    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUMMBUFS,0,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());
    if (mbuf_pool == NULL)
    {
        rte_exit(EXIT_FAILURE, "Could Not Create Buffer\n");
    }


    // 初始化网卡,启动DPDK
    ifIndex_init(mbuf_pool);
    rte_eth_macaddr_get(g_dpdk_ifIndex,(struct rte_ether_addr* )g_src_mac);


    // 初始化定时器
    rte_timer_subsystem_init();
    struct rte_timer arp_timer;
    rte_timer_init(&arp_timer);

    // 设置定时器频率
    uint64_t  hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();
    // PERIODICAL 循环触发 SINGLE 单次触发
    // 设置了，但是没有调用
    rte_timer_reset(&arp_timer,hz,PERIODICAL,lcore_id,arp_request_timer_cb,mbuf_pool);

    // 初始化环
    struct inout_ring *ring = ringInstance();
	if (ring == NULL) {
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
	}

	if (ring->in == NULL) {
		ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}


    // 初始化XXXXXX
    rte_eal_remote_launch(pkt_process, mbuf_pool, rte_get_next_lcore(lcore_id, 1, 0));

	while (1) 
    {
		// rx
		struct rte_mbuf *rx[BURSTSIZE];
		unsigned num_recvd = rte_eth_rx_burst(g_dpdk_ifIndex, 0, rx, BURSTSIZE);
		if (num_recvd > BURSTSIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		} else if (num_recvd > 0) {

			rte_ring_sp_enqueue_burst(ring->in, (void**)rx, num_recvd, NULL);
		}

		
		// tx
		struct rte_mbuf *tx[BURSTSIZE];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx, BURSTSIZE, NULL);
		if (nb_tx > 0) {

			rte_eth_tx_burst(g_dpdk_ifIndex, 0, tx, nb_tx);

			unsigned i = 0;
			for (i = 0;i < nb_tx;i ++) {
                //printf ("发送一个数据包");
				rte_pktmbuf_free(tx[i]);
			}
			
		}
	
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}

	}


}



static int pkt_process(void *arg)
{
    // 获取内存池
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    // 获取收发缓冲区
	struct inout_ring *ring = ringInstance();



    while (1)
    {
        // 接受数据包的缓冲区
        struct rte_mbuf *mbufs[BURSTSIZE];
        unsigned recv_package = rte_ring_mc_dequeue_burst(ring->in, (void **)mbufs, BURSTSIZE, NULL);

        // 遍历处理每个数据包
        for (unsigned index = 0; index < recv_package; ++index)
        {
            //分析一层报头
            printf("接收到数据包\n");
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[index], struct rte_ether_hdr*);

            // 辨别二层协议
            if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
            {
                // 解析ARP报文
                struct rte_arp_hdr* arp_hdr = rte_pktmbuf_mtod_offset(mbufs[index], struct rte_arp_hdr*,sizeof(struct rte_ether_hdr));

                /*
                struct in_addr addr;
                addr.s_addr = arp_hdr->arp_data.arp_tip;
                struct in_addr addr2;
                addr2.s_addr = arp_hdr->arp_data.arp_sip;
                */
                //printf("接收到arp报文 ---> src: %s dst %s ", inet_ntoa(addr));
                // 比对IP，处理自身相关数据包
                if (arp_hdr->arp_data.arp_tip == g_src_arp_ip)
                {
                    printf("接受到本机报文\n");
                    //分别处理ARP的发送和接受请求
                    if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST))
                    {
                        // 处理接收到的ARP请求 构建对应的ARP响应
                        struct rte_mbuf* arpbuf = send_arp_pack(mbuf_pool,RTE_ARP_OP_REPLY,arp_hdr->arp_data.arp_sha.addr_bytes,arp_hdr->arp_data.arp_tip,arp_hdr->arp_data.arp_sip);
                        rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
                        //rte_pktmbuf_free(mbufs[index]);
                    }
                    else if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY))
                    {
                        // 处理ARP响应，添加到ARP缓存
                        struct arp_table* table = arp_table_instance();
                        // 获取ARP核心的MAC和IP地址
                        uint8_t* arp_hw_addr = get_dst_mac(arp_hdr->arp_data.arp_sip);
                        if (arp_hw_addr == NULL)
                        {
                            struct arp_entry* entry = rte_malloc("arp entry",sizeof(struct arp_entry), 0);
                            if (entry)
                            {
                                memset(entry, 0, sizeof(struct arp_entry));
                                entry->ip = arp_hdr->arp_data.arp_sip;
                                rte_memcpy(entry->hwaddr, arp_hdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
                                entry->type = ARP_ENTRY_STATUS_DYNAMIC;
                                LL_ADD(entry,table->entries);
                                table->count ++;
                            }
                        }
                        // todo 为啥这块释放了内存
                        rte_pktmbuf_free(mbufs[index]);
                    }
                    continue;

                }
            }
            else if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
            {
                // 处理IPV4数据包
                struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[index], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
                // 分别处理TCP/UDP/ICMP数据包
                if (iphdr->next_proto_id == IPPROTO_UDP)
                {
                    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

                    // 构建UDP回应五元组
                    rte_memcpy(g_dst_mac, eth_hdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				    rte_memcpy(&g_src_ip, &iphdr->dst_addr, sizeof(uint32_t));
				    rte_memcpy(&g_dst_ip, &iphdr->src_addr, sizeof(uint32_t));
				    rte_memcpy(&g_src_port, &udphdr->dst_port, sizeof(uint16_t));
				    rte_memcpy(&g_dst_port, &udphdr->src_port, sizeof(uint16_t));

                    uint16_t length = ntohs(udphdr->dgram_len);
                    *((char*)udphdr + length) = '\0';
                    struct rte_mbuf *txbuf = send_udp_pack(mbuf_pool,(uint8_t *)(udphdr + 1), length);
                    rte_ring_mp_enqueue_burst(ring->out,(void**)&txbuf,1,NULL);
                    rte_pktmbuf_free(mbufs[index]);
                }
                else if (iphdr->next_proto_id == IPPROTO_ICMP)
                {
                    // 处理ICMP报头
                    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
                    printf("接收到icmp报文 --->");

                    if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST)
                    {
                        struct rte_mbuf *txbuf = send_icmp_pack(mbuf_pool, eth_hdr->s_addr.addr_bytes,
						iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

                        rte_ring_mp_enqueue_burst(ring->out, (void**)&txbuf, 1, NULL);
                        rte_pktmbuf_free(mbufs[index]);
                    }
                }
            }
            else
            {
                continue;
            }

        }
    }
    return 0;
}