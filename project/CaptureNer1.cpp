// CaptureNer1.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "pcap.h"
#include "windows.h"
#include "protocols.h"
#include <conio.h>

//using namespace std;
//#define LINE_LEN 16 //用于打印从文件捕获的数据包
//#include <string>

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#define LINE_LEN 16



/* 4字节的IP地址 */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header{
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 服务类型(Type of service) 8bit
	u_short tlen;           // 总长(Total length) 16bit
	u_short identification; // 标识(Identification)16bit
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)8bit
	u_char  proto;          // 协议(Protocol)8bit
	u_short crc;            // 首部校验和(Header checksum)16bit
	ip_address  saddr;      // 源地址(Source address)32bit
	ip_address  daddr;      // 目的地址(Destination address)32bit
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;



//Statements
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void printInfo(const struct pcap_pkthdr *header, const u_char *pkt_data);
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
int print_file_list(char **file_name_list, char *searchStr);
int capture();
int printFilePkt();
char* get_time_str(char* pass_time_str);
int print_count = 0;//use it for print control
pcap_t *adhandle;  //use for starting and end looping
pcap_dumper_t *dumpfile;//to store packet
LRESULT CALLBACK kb_proc(int code, WPARAM w, LPARAM l);
pcap_t *fp;//for file handler
//void captureThread(){
//	capture(adhandle);
//}

HHOOK g_kb_hook = 0;//use it for exit capture process and back to main menu
MSG msg;
LRESULT CALLBACK kb_proc(int code, WPARAM w, LPARAM l)
{
	printf((w == WM_KEYDOWN) ? "Key 0x%x pressed.\n" : "Key 0x%x up.\n", ((PKBDLLHOOKSTRUCT)l)->vkCode);
	if (((PKBDLLHOOKSTRUCT)l)->vkCode == VK_ESCAPE){
		pcap_breakloop(adhandle);
		pcap_dump_flush(dumpfile);
		pcap_dump_close(dumpfile);
		pcap_close(adhandle);
	}
	return CallNextHookEx(g_kb_hook, code, w, l);
}



int main()
{
	int judgeexit = 0;
	while (!judgeexit)
	{
		system("cls");
		int selection;
		printf("Welcome!\n");
		printf("1. Start capture!\n");
		printf("2. Parse a file.\n");
		printf("3. Exit. \n");
		printf("Choose one option: ");
		scanf("%d", &selection);

		switch (selection)
		{
		case (1) : 
		{
					 capture();
					 break;
		}
		case (2) : 
			printFilePkt(); 
			break;
		case (3) : 
			exit(EXIT_SUCCESS);
		default:
			printf("\n\tWRONG INPUT! CHECK AGAIN!\n"); 
			system("pause"); 
			break;
		}
	}


}

int capture()
{
	pcap_if_t *alldevs;//设备列表
	pcap_if_t *d;
	int inum;
	int i = 0;
	
	char errbuf[PCAP_ERRBUF_SIZE];//错误缓冲池
	u_int netmask;//掩码
	char packet_filter[] = "ip";//数据包过滤表达式 ip and udp
	struct bpf_program fcode;



	/* 获得设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
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
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* 打开适配器 */
	if ((adhandle = pcap_open(d->name,  // 设备名
		65536,     // 要捕捉的数据包的部分 
		// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
		1000,      // 读取超时时间
		NULL,      // 远程机器验证
		errbuf     // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* 发生错误则释放设备列表并结束 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 检查数据链路层，只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 发生错误则释放设备列表并结束*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 发生错误则释放设备列表并结束*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 发生错误则释放设备列表并结束*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 打开堆文件.只有当接口打开时，调用 pcap_dump_open() 才是有效的*/
	char timestr2file[16];
	time_t time2file;
	time(&time2file);
	struct tm *ltime = localtime(&time2file);
	strftime(timestr2file, sizeof timestr2file, "%Y%m%d%H%M%S", ltime);
	strcat(timestr2file,".dumpfile");
	dumpfile = pcap_dump_open(adhandle, timestr2file);
	if (dumpfile == NULL)
	{
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}

	//显示正在监听...
	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	//use for accept escape to main menu
	g_kb_hook = SetWindowsHookEx(WH_KEYBOARD_LL, kb_proc, GetModuleHandle(NULL), 0);
	if (g_kb_hook == NULL)
	{
		printf("安装钩子出错\n");
		return 0;
	};

	/* 开始捕捉 */
	pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);

	UnhookWindowsHookEx(g_kb_hook);
	return 0;
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* 保存数据包到堆文件 */
	pcap_dump(dumpfile, header, pkt_data);

	printInfo(header, pkt_data);//解析头内容

	//pcap_breakloop(adhandle);
	PeekMessage(&msg, NULL, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE);
	TranslateMessage(&msg);
	DispatchMessage(&msg);
}

void printInfo(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	
	char timestr[16];

	/* 将时间戳转换成可识别的格式 */
	time_t local_tv_sec = header->ts.tv_sec;
	struct tm *ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* 打印数据包的时间戳和长度 */
	printf("%s.%.6d Length:%d ", timestr, header->ts.tv_usec, header->len);

	/* 获得IP数据包头部的位置 */
	ip_header *ih = (ip_header *)(pkt_data + 14); //以太网头部长度

	/* 打印IP地址 */
	printf("[ %d.%d.%d.%d --> %d.%d.%d.%d ]\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4
		);

	//ip版本(4 bit ,ver_ihl is 8bit)
	printf("Version:ipv%d .\n", ih->ver_ihl >> 4);//unsigned char move right 4 bit

	//ip header length(4 bit)
	printf("IP_header_length: %d DW.\n", ih->ver_ihl & 0x0F);

	//type of service
	printf("Type of Service: %d.\n", ih->tos);

	//(Total length) 16bit
	printf("Total length: %d Bytes.\n", ih->tlen);

	//identification
	printf("Identification: %d.\n", ih->identification);

	// 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	char* DF = "Allow Fragment";
	char* MF = "No MF";
	if ((ih->flags_fo & 0x4000) == 0x4000){ DF = "Don't Fragment"; }
	if ((ih->flags_fo & 0x2000) == 0x2000){ MF = "More Fragment"; }
	printf("Flags Fragment: %s. %s.\n", DF, MF);
	printf("Offset: %d.\n", ih->flags_fo & 0x1FFF);

	// 存活时间(Time to live)8bit
	printf("Time to Live: %ds.\n", ih->ttl);

	// 协议(Protocol)8bit
	printf("Protocal: %s.\n", protocols::getname(ih->proto));

	//checksum
	printf("Checksum: %x.\n\n", ih->crc);

}



int printFilePkt()
{
	
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	char to_search[16];
	printf("You can search files with the format \"yyyyMMddHHMMSS\", e.g. 20141103\n");
	scanf("%s", &to_search);

	//TODO: search dump files
	char **file_name_list = new char*[100];
	int get_file_selection;
	int status_get_list = print_file_list(file_name_list, to_search);
	if (status_get_list == -1)
	{
		printf("No file coressponding to your input.");
		Sleep(2000);
		return -1;
	}
	printf("choose a file to parse it>>");
	scanf("%d", &get_file_selection);
	while (get_file_selection > status_get_list || get_file_selection <= 0)
	{
		printf("Your selection out of range. Choose AGAIN to parse it>>");
		scanf("%d", &get_file_selection);
	}

	//do
	//{
	//	printf("choose a file to parse it>>");
	//	scanf("%d", &get_file_selection);
	//} while (get_file_selection > status_get_list || get_file_selection <=0);


	/* 根据新WinPcap语法创建一个源字符串 */
	if (pcap_createsrcstr(source,         // 源字符串
		PCAP_SRC_FILE,  // 指明我们要打开的是文件
		NULL,           // 远程主机
		NULL,           // 远程主机端口
		file_name_list[get_file_selection],        // 我们要打开的文件名
		errbuf          // 错误缓冲区
		) != 0)
	{
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}

	/* 打开捕获文件 */
	if ((fp = pcap_open(source,         // 设备名
		65536,          // 要捕捉的数据包的部分
		// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,     // 混杂模式
		1000,              // 读取超时时间
		NULL,              // 远程机器验证
		errbuf         // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		return -1;
	}


	// 读取并解析数据包，直到EOF为真
	int loop_status = pcap_loop(fp, 0, dispatcher_handler, NULL);
	if (loop_status=0)
	{
		printf("This file is EMPTY!");
	}
	else if (loop_status == -2)
	{
		printf("exit viewing");
	}
	else if (loop_status < 0)
	{
		printf("An error occurred");
	}
	system("pause");

	return 0;
}



void dispatcher_handler(u_char *temp1,
	const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	
	printInfo(header, pkt_data);
	print_count++;
	if (print_count%5 == 0)
	{ 
		//system("pause");
		/*while (char quit_enter = getchar() != '\n')
		{
			if (quit_enter == 'q' || quit_enter == 'Q')
			{
				pcap_breakloop(fp);
			}
		}*/
		char quit_enter = _getch();
		if (quit_enter == 'q' || quit_enter == 'Q')
		{
			pcap_breakloop(fp);
			pcap_close(fp);
		}
	}
}

int print_file_list(char **file_name_list, char *searchStr)
{
	char whole_search_str[30] = "*";
	char *file_suffix = "*.dumpfile";
	strcat(whole_search_str, searchStr);
	strcat(whole_search_str, file_suffix);

	long handle;
	int i = 1;
	struct _finddata_t fileinfo;
	handle = _findfirst(whole_search_str, &fileinfo);
	if (-1 == handle) return -1;
	printf("%d. %s\n", i, fileinfo.name);
	file_name_list[i] = new char[strlen(fileinfo.name)];
	strcpy(file_name_list[i], fileinfo.name);
	while (!_findnext(handle, &fileinfo))
	{

		printf("%d. %s\n", ++i, fileinfo.name);
		file_name_list[i] = new char[strlen(fileinfo.name)];
		strcpy(file_name_list[i], fileinfo.name);
	}
	_findclose(handle);
	return i;
}

