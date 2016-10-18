// CaptureNer1.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "pcap.h"
#include "windows.h"
#include "protocols.h"
#include <conio.h>

//using namespace std;
//#define LINE_LEN 16 //���ڴ�ӡ���ļ���������ݰ�
//#include <string>

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#define LINE_LEN 16



/* 4�ֽڵ�IP��ַ */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 �ײ� */
typedef struct ip_header{
	u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
	u_char  tos;            // ��������(Type of service) 8bit
	u_short tlen;           // �ܳ�(Total length) 16bit
	u_short identification; // ��ʶ(Identification)16bit
	u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	u_char  ttl;            // ���ʱ��(Time to live)8bit
	u_char  proto;          // Э��(Protocol)8bit
	u_short crc;            // �ײ�У���(Header checksum)16bit
	ip_address  saddr;      // Դ��ַ(Source address)32bit
	ip_address  daddr;      // Ŀ�ĵ�ַ(Destination address)32bit
	u_int   op_pad;         // ѡ�������(Option + Padding)
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
	pcap_if_t *alldevs;//�豸�б�
	pcap_if_t *d;
	int inum;
	int i = 0;
	
	char errbuf[PCAP_ERRBUF_SIZE];//���󻺳��
	u_int netmask;//����
	char packet_filter[] = "ip";//���ݰ����˱��ʽ ip and udp
	struct bpf_program fcode;



	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
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
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת����ѡ�豸 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* �������� */
	if ((adhandle = pcap_open(d->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��Ĳ��� 
		// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
		1000,      // ��ȡ��ʱʱ��
		NULL,      // Զ�̻�����֤
		errbuf     // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* �����������ͷ��豸�б����� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ���������·�㣬ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �����������ͷ��豸�б�����*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �����������ͷ��豸�б�����*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �����������ͷ��豸�б�����*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* �򿪶��ļ�.ֻ�е��ӿڴ�ʱ������ pcap_dump_open() ������Ч��*/
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

	//��ʾ���ڼ���...
	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	//use for accept escape to main menu
	g_kb_hook = SetWindowsHookEx(WH_KEYBOARD_LL, kb_proc, GetModuleHandle(NULL), 0);
	if (g_kb_hook == NULL)
	{
		printf("��װ���ӳ���\n");
		return 0;
	};

	/* ��ʼ��׽ */
	pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);

	UnhookWindowsHookEx(g_kb_hook);
	return 0;
}

/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* �������ݰ������ļ� */
	pcap_dump(dumpfile, header, pkt_data);

	printInfo(header, pkt_data);//����ͷ����

	//pcap_breakloop(adhandle);
	PeekMessage(&msg, NULL, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE);
	TranslateMessage(&msg);
	DispatchMessage(&msg);
}

void printInfo(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	
	char timestr[16];

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	time_t local_tv_sec = header->ts.tv_sec;
	struct tm *ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* ��ӡ���ݰ���ʱ����ͳ��� */
	printf("%s.%.6d Length:%d ", timestr, header->ts.tv_usec, header->len);

	/* ���IP���ݰ�ͷ����λ�� */
	ip_header *ih = (ip_header *)(pkt_data + 14); //��̫��ͷ������

	/* ��ӡIP��ַ */
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

	//ip�汾(4 bit ,ver_ihl is 8bit)
	printf("Version:ipv%d .\n", ih->ver_ihl >> 4);//unsigned char move right 4 bit

	//ip header length(4 bit)
	printf("IP_header_length: %d DW.\n", ih->ver_ihl & 0x0F);

	//type of service
	printf("Type of Service: %d.\n", ih->tos);

	//(Total length) 16bit
	printf("Total length: %d Bytes.\n", ih->tlen);

	//identification
	printf("Identification: %d.\n", ih->identification);

	// ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	char* DF = "Allow Fragment";
	char* MF = "No MF";
	if ((ih->flags_fo & 0x4000) == 0x4000){ DF = "Don't Fragment"; }
	if ((ih->flags_fo & 0x2000) == 0x2000){ MF = "More Fragment"; }
	printf("Flags Fragment: %s. %s.\n", DF, MF);
	printf("Offset: %d.\n", ih->flags_fo & 0x1FFF);

	// ���ʱ��(Time to live)8bit
	printf("Time to Live: %ds.\n", ih->ttl);

	// Э��(Protocol)8bit
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


	/* ������WinPcap�﷨����һ��Դ�ַ��� */
	if (pcap_createsrcstr(source,         // Դ�ַ���
		PCAP_SRC_FILE,  // ָ������Ҫ�򿪵����ļ�
		NULL,           // Զ������
		NULL,           // Զ�������˿�
		file_name_list[get_file_selection],        // ����Ҫ�򿪵��ļ���
		errbuf          // ���󻺳���
		) != 0)
	{
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}

	/* �򿪲����ļ� */
	if ((fp = pcap_open(source,         // �豸��
		65536,          // Ҫ��׽�����ݰ��Ĳ���
		// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,     // ����ģʽ
		1000,              // ��ȡ��ʱʱ��
		NULL,              // Զ�̻�����֤
		errbuf         // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		return -1;
	}


	// ��ȡ���������ݰ���ֱ��EOFΪ��
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

