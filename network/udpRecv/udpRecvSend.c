#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_icmp.h>
#include <rte_timer.h>

#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>


#include <rte_malloc.h>

// 10ms*10000*12 一分钟
#define TIMER_RESOLUTION_CYCLES 20000000000ULL
#define TIME_RESOLUTION_CYCLES 20000000000ULL

// ARP表 ARP规则定义
#define ARP_ENTRY_STATUS_DYNAMIC 0
#define ARP_ENTRY_STATUS_STATIC 1


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
        arpt = rte_malloc("arp_table", sizeof(struct arp_table), 0);
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

static void 
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

// 打印MAC地址
static inline void print_mac(const char* what, const struct rte_ether_addr* eth_addr)
{
    // what 固定输出在屏幕上的内容, 
    // MAC地址 (struct rte_ether_addr*) uint8
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf,RTE_ETHER_ADDR_FMT_SIZE,eth_addr);
    printf("%s%s",what,buf);
}

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



// 数据包发送五元组构建
static uint16_t g_src_port;
static uint16_t g_dst_port;


static uint32_t g_src_ip;
static uint32_t g_dst_ip;

static uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
static uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];

static uint8_t g_default_arp_mac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t g_default_eth_mac[RTE_ETHER_ADDR_LEN] = {0x00};

// UDP接受的广播信息IP变成广播地址，为了避免ARP受影响，从新生成变量
static uint32_t g_src_arp_ip = MAKE_IPVE_ADDR(192,168,18,102);
// 172.20.4.33
// static uint32_t g_src_arp_ip = MAKE_IPVE_ADDR(172,20,4,33);



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
    rte_memcpy(ethhdr->s_addr.addr_bytes, g_src_arp_ip, RTE_ETHER_ADDR_LEN);

    // 目的IP地址
    if (!strncmp ((const char*)dst_mac, (const char*)g_default_arp_mac, RTE_ETHER_ADDR_LEN))
    {
        // 每一位都是1,代表是没有ARP地址的信息
        rte_memcpy(ethhdr->d_addr.addr_bytes, g_default_eth_mac, RTE_ETHER_ADDR_LEN);
    }
    else
    {
        rte_memcpy(ethhdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
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
    struct rte_mbuf* arpbuf = NULL ;
    //rte_eth_tx_burst(g_dpdk_ifIndex,0,&arpbuf,1);
    //rte_pktmbuf_free(arpbuf);

    for (int index = 1; index < 254; ++index)
    {
        uint32_t dstip = (g_src_arp_ip & 0x00FFFFFF) | (0xFF000000 & (index << 24));
        struct in_addr addr;
        addr.s_addr = dstip;
        //printf(" --> arp send: %s\n", inet_ntoa(addr));
        addr.s_addr = g_src_arp_ip;
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
        rte_eth_tx_burst(g_dpdk_ifIndex,0,&arpbuf,1);
        rte_pktmbuf_free(arpbuf);
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


    static uint64_t prev_tsc = 0;
    static uint64_t cur_tsc;
    uint64_t diff_tsc;
    
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

            
            // 处理ARP数据包
            if (ethhdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
            {
                // 只处理广播过来和自己有关的数据包，其他人的数据包不处理
                // 解析出来ARP头
                struct rte_arp_hdr* arp_hdr = rte_pktmbuf_mtod_offset(mbufs[index], struct rte_arp_hdr*,sizeof(struct rte_ether_hdr));
                // 比对本身的IP
				struct in_addr addr;
				addr.s_addr = arp_hdr->arp_data.arp_tip;
				printf("arp ---> src: %s ", inet_ntoa(addr));
                if (arp_hdr->arp_data.arp_tip == g_src_arp_ip)
                {
                    // 分别处理ARP发送和接受的数据包
                    if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST))
                    {
                        // 收到ARP请求，发送响应
                        struct rte_mbuf* arpbuf = send_arp_pack(mbuf_pool,RTE_ARP_OP_REPLY,arp_hdr->arp_data.arp_sha.addr_bytes,arp_hdr->arp_data.arp_tip,arp_hdr->arp_data.arp_sip);
                        rte_eth_tx_burst(g_dpdk_ifIndex,0,&arpbuf,1);
                        rte_pktmbuf_free(arpbuf);
                        rte_pktmbuf_free(mbufs[index]);
                    }
                    else if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY))
                    {
                        // 收到ARP响应，查看自己ARP表中是否存在数据
                        printf("resopnse!\n");
                        struct arp_table* table = arp_table_instance();
                        uint8_t* hwaddr =  get_dst_mac(arp_hdr->arp_data.arp_sip);
                        if (hwaddr == NULL)
                        {
                            
                            struct arp_entry* entry = rte_malloc("arp entry", sizeof(struct arp_entry),0);
                            if (entry)
                            {
                                memset(entry, 0, sizeof(struct arp_entry));
                                entry->ip = arp_hdr->arp_data.arp_sip;
                                rte_memcpy(entry->hwaddr, arp_hdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
                                entry->type = ARP_ENTRY_STATUS_DYNAMIC;
                                LL_ADD(entry,table->entries);
                                table->count ++;
                                struct in_addr addr;
                                addr.s_addr = entry->ip;
                                print_ethaddr("mac ->",(struct rte_ether_addr *)entry->hwaddr);
                                printf(" --> arp send: %s\n", inet_ntoa(addr));
                            }
                        }
                    }

                }
                continue;
            }

            

            
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

                //struct in_addr addr;
                //addr.s_addr = iphdr->src_addr;
                //printf("src :%s:%d\n",inet_ntoa(addr),  ntohs(udphdr->src_port));
                //addr.s_addr = iphdr->dst_addr;
                //printf("dst :%s:%d\n",inet_ntoa(addr),  ntohs(udphdr->dst_port));
                //printf ("message :%s\n",(char *)(udphdr + 1));


                struct rte_mbuf *txbuf = send_udp_pack(mbuf_pool,(uint8_t *)(udphdr + 1), length);
                // 从某个网卡，某个队列，发送某个内存，发送一个包
                rte_eth_tx_burst(g_dpdk_ifIndex,0,&txbuf,1);
                rte_pktmbuf_free(txbuf);


                // 释放内存
                rte_pktmbuf_free(mbufs[index]);
            } 

            if (iphdr->next_proto_id == IPPROTO_ICMP)
            {
				struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

				
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("icmp ---> src: %s \n", inet_ntoa(addr));

				
				if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) 
                {

					addr.s_addr = iphdr->dst_addr;
					printf(" local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);
				

					struct rte_mbuf *txbuf = send_icmp_pack(mbuf_pool, ethhdr->s_addr.addr_bytes, iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
					rte_eth_tx_burst(g_dpdk_ifIndex, 0, &txbuf, 1);
					rte_pktmbuf_free(txbuf);

					rte_pktmbuf_free(mbufs[index]);
				}                
            }

        }
        // 每一轮大循环，触发一次定时器任务
        // cur当前时间,prev上次触发时间，求差值

        cur_tsc =  rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES)
        {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }
        
        /*
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
        */
    }
    
}

// 172.20.4.33
// 192.168.18.155
// 11000000 10101000 00010010 10011011
// 