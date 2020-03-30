#ifdef _MSC_VER
//防止ms编译器错误
#define _CRT_SECURE_NO_WARNINGS
#define _XKEYCHECK_H
#endif

#include "pcap.h"
#include <ctime>
#include <map>
#include <string>
#include <iostream>
  /* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 8位服务类型(Type of service) 
	u_short tlen;           // 16位总长(Total length) 
	u_short identification; // 16位标识(Identification)
	u_short flags_fo;       // 3位标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 8位存活时间(Time to live)
	u_char  proto;          // 8位协议(Protocol)
	u_short crc;            // 16位首部校验和(Header checksum)
	ip_address  saddr;      // 32位源地址(Source address)
	ip_address  daddr;      // 32位目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

struct macinfo
{
	u_char dstmac[6];
	u_char srcmac[6];
	u_char type[2];
	macinfo() {}
	macinfo(const u_char*src)
	{
		int tot = 0;
		for (int i = 0; i < 6; i++)dstmac[i] = src[tot++];
		for (int i = 0; i < 6; i++)srcmac[i] = src[tot++];
		for (int i = 0; i < 2; i++)type[i] = src[tot++];
	}
	void printdstmac()
	{
		for (int i = 0; i < 6; i++)
		{
			if (i)printf("-");
			printf("%02X", dstmac[i]);
		}
	}
	void printsrcmac()
	{
		for (int i = 0; i < 6; i++)
		{
			if (i)printf("-");
			printf("%02X", srcmac[i]);
		}
	}
	std::string getsrcmac()
	{
		std::string a;
		for (int i = 0; i < 6; i++)
		{
			char bin[10];
			if (i)a.push_back('-');
			sprintf(bin, "%02X", srcmac[i]);
			a += bin;
		}
		return a;
	}
	std::string getdstmac()
	{
		std::string a;
		for (int i = 0; i < 6; i++)
		{
			char bin[10];
			if (i)a.push_back('-');
			sprintf(bin, "%02X", dstmac[i]);
			a += bin;
		}
		return a;
	}
};

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
pcap_if_t* alldevs;
pcap_if_t* d;
int inum;
int i = 0;
pcap_t* adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
u_int netmask;
char packet_filter[] = "ip and udp";
struct bpf_program fcode;

time_t timep;
struct tm* thistime;
std::map<std::string, int>srcmac;
std::map<std::string, int>dstmac;//记录源mac和目的mac的发送信息之和
std::map<std::string, int>srcip;
std::map<std::string, int>dstip;//记录源ip和目的ip的发送信息之和
int cnt = 0;
int sumlen = 0;//记录总流量
void pre()//预处理
{
    /*抓取当前时间*/
	time(&timep);
	thistime = gmtime(&timep);
	
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return;
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}

	printf("请选择查询的网卡接口 (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return;
	}

}
void showmac()
{
	printf("不同源mac地址的发送情况：\n");
	for (auto e = srcmac.begin(); e != srcmac.end(); e++)
	{
		std::cout << e->first << " 一共发送了" << e->second << "长度的信息" << std::endl;
	}
	printf("不同目的mac地址的发送情况：\n");
	for (auto e = dstmac.begin(); e != dstmac.end(); e++)
	{
		std::cout << e->first << " 一共发送了" << e->second << "长度的信息" << std::endl;
	}
}
void showip()
{
	printf("不同源ip地址的发送情况：\n");
	for (auto e = srcip.begin(); e != srcip.end(); e++)
	{
		std::cout << e->first << " 一共发送了" << e->second << "长度的信息" << std::endl;
	}
	printf("不同目的ip地址的发送情况：\n");
	for (auto e = dstip.begin(); e != dstip.end(); e++)
	{
		std::cout << e->first << " 一共发送了" << e->second << "长度的信息" << std::endl;
	}
}
int main()
{
	pre();
	printf("\n正在侦听 %s 上的网络流...\n", d->description);

	/* 选择成功，把其他device free掉 */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}
/*
struct pcap_pkthdr
{
	 struct timeval ts;  ts是一个结构struct timeval
	 bpf_u_int32 caplen;  表示抓到的数据长度
	 bpf_u_int32len;   表示数据包的实际长度
}*/
/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	ip_header* ih;//ih:ip头文件
	udp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	macinfo mh(pkt_data);
	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	
	/* print timestamp and length of the packet */
	printf("%04d-%02d-%02d %s,", 1900 + thistime->tm_year,1 + thistime->tm_mon,thistime->tm_mday,timestr);
	
	
	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	mh.printsrcmac();
	/* print ip addresses and udp ports */
	std::string srcipstr, dstipstr;//提取出ip地址
	char sub[24];
	sprintf(sub, "%d.%d.%d.%d",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4);
	srcipstr = sub;
	sprintf(sub, "%d.%d.%d.%d",
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
	dstipstr = sub;

	printf(",%d.%d.%d.%d,",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4);
	mh.printdstmac();
	printf(",%d.%d.%d.%d,",
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
	printf("%d\n", header->len);
	srcip[srcipstr] += header->len;
	dstip[dstipstr] += header->len;
	srcmac[mh.getsrcmac()] += header->len;
	dstmac[mh.getdstmac()] += header->len;//将数据长度更新到map里
	
	++cnt;
	if (cnt % 60 == 0) { showmac(); showip(); } //每隔60次数据展示mac和ip信息
	sumlen += header->len;
	if (sumlen >= 1024 * 1024 * 0.05)printf("数据已经超过0.05M，流量预警!\n");//流量预警

}
