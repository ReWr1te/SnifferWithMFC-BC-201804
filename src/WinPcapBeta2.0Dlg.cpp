
// WinPcapBeta2.0Dlg.cpp : 实现文件
// 自动生成的函数或代码段与我编写的部分
// 大括号风格不同，修改时注意区别

#include "stdafx.h"
#include "Resource.h"
#include "WinPcapBeta2.0.h"
#include "WinPcapBeta2.0Dlg.h"
#include "afxdialogex.h"
#include "pcap.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/* 定义用于输出包内容的常量 */
// #define LINE_LEN 16
// #define MAX_ADDR_LEN 16

/* 定义全局变量 */
pcap_if_t *alldevs;
pcap_if_t *d;
pcap_t *adhandle;

int inum;
int i = 0;
int res;
int count = 1;
int max_count = 10;
int row;

u_int netmask;
char packet_filter[] = "ip";
struct bpf_program fcode;

struct pcap_pkthdr *header;
const u_char *pkt_data;
ip_header *ih;

time_t local_tv_sec;
struct tm ltime;
char timestr[16];

char errbuf[PCAP_ERRBUF_SIZE];

/* 自动生成的函数（未作修改） */
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()

// CWinPcapBeta20Dlg 对话框
CWinPcapBeta20Dlg::CWinPcapBeta20Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_WINPCAPBETA20_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CWinPcapBeta20Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, list);
}

BEGIN_MESSAGE_MAP(CWinPcapBeta20Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CWinPcapBeta20Dlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CWinPcapBeta20Dlg::OnBnClickedCancel)
	ON_EN_CHANGE(IDC_EDIT1, &CWinPcapBeta20Dlg::OnEnChangeEdit1)
	ON_BN_CLICKED(IDC_BUTTON1, &CWinPcapBeta20Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CWinPcapBeta20Dlg::OnBnClickedButton2)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CWinPcapBeta20Dlg::OnLvnItemchangedList1)
	ON_EN_CHANGE(IDC_EDIT2, &CWinPcapBeta20Dlg::OnEnChangeEdit2)
END_MESSAGE_MAP()

/* CWinPcapBeta20Dlg 消息处理程序，做了相应界面初始化*/
BOOL CWinPcapBeta20Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	CString str;
	CRect rect;
	list.GetClientRect(&rect);
	list.InsertColumn(0, _T("设备编号"), LVCFMT_CENTER, rect.Width() / 5, 0);
	list.InsertColumn(1, _T("设备名称"), LVCFMT_CENTER, rect.Width() / (5 / 2), 0);
	list.InsertColumn(2, _T("设备描述"), LVCFMT_CENTER, rect.Width() / (5 / 2), 0);

	/* 获得设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		MessageBox(L"寻找设备出错，请确认WinPcap正确安装，并重新启动应用", L"警告", MB_OK);
		exit(1);
	}

	/* 显示设备列表 */
	for (d = alldevs; d; d = d->next) {
		str.Format(_T("%d"), ++i);
		int row = list.InsertItem(i, str);
		// list.SetItemText(row, 0, str);
		str = d->name;
		list.SetItemText(row, 1, str);
		str = d->description;
		list.SetItemText(row, 2, str);
	}

	/* 未找到设备警告 */
	if (i == 0) {
		MessageBox(L"没有找到设备，请确保WinPcap已正确安装，并重新启动应用", L"警告", MB_OK);
		return FALSE;
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CWinPcapBeta20Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CWinPcapBeta20Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标显示。
HCURSOR CWinPcapBeta20Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/* 包处理函数，自己编写，目前只MFC程序应用了Ethernet和IP */
/* TCP 处理 */
void tcp_protocol_packet_handler(
	u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data
) {
	struct tcp_header *tcp_protocol;
	u_short sport;
	u_short dport;
	int header_length;
	u_short windows;
	u_short urgent_pointer;
	u_int sequence;
	u_int acknowledgement;
	u_short checksum;
	u_char flags;

	printf("===========TCP Protocol===========\n");

	tcp_protocol = (struct tcp_header*)(pkt_data + 14 + 20);
	sport = ntohs(tcp_protocol->sport);
	dport = ntohs(tcp_protocol->dport);
	header_length = tcp_protocol->offset * 4;
	sequence = ntohl(tcp_protocol->sequence);
	acknowledgement = ntohl(tcp_protocol->ack);
	windows = ntohs(tcp_protocol->windows);
	urgent_pointer = ntohs(tcp_protocol->urgent_pointer);
	flags = tcp_protocol->flags;
	checksum = ntohs(tcp_protocol->checksum);

	printf("%d0%d%d%c%d", header_length, sport, dport, flags, windows);

	switch (dport) {
	default:
		break;
	}

	if (flags & 0x08) printf("PSH");
	if (flags & 0x10) printf("ACK");
	if (flags & 0x02) printf("SYN");
	if (flags & 0x20) printf("URG");
	if (flags & 0x01) printf("FIN");
	if (flags & 0x04) printf("RST");
	printf("\n");
}

/* UDP 处理 */
void udp_protocol_packet_handler(
	u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data
) {
	struct udp_header* udp_protocol;
	u_short sport;
	u_short dport;
	u_short datalen;

	udp_protocol = (struct udp_header*)(pkt_data + 14 + 20);
	sport = ntohs(udp_protocol->sport);
	dport = ntohs(udp_protocol->dport);
	datalen = ntohs(udp_protocol->len);

	printf("0%d%d%d", datalen, sport, dport);
}

/* ICMP 处理 */
void icmp_protocol_packet_handler(
	u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data
) {
	struct icmp_header *icmp_protocol;
	u_short type;
	u_short datalen;
	u_int init_time;
	u_int recv_time;
	u_int send_time;

	icmp_protocol = (struct icmp_header*)(pkt_data + 14 + 20);
	datalen = sizeof(icmp_protocol);
	type = icmp_protocol->type;

	/*init_time = icmp_protocol->init_time;
	recv_time = icmp_protocol->recv_time;
	send_time = icmp_protocol->send_time;
	printf("%d%c%d%d%d", datalen, type, init_time, recv_time, send_time);*/

	printf("===========ICMP Protocol==========\n");
	printf("Type: %d ", type);

	switch (icmp_protocol->type) {
	case 8:
		printf("(request)\n"); // 回显请求报文
		break;
	case 0:
		printf("(reply)\n"); // 回显应答报文
		break;
	default:
		printf("\n");
		break;
	}

	printf("Code: %d\n", icmp_protocol->code);
	printf("CheckSum: 0x%.4x\n", ntohs(icmp_protocol->checksum));
	printf("Identification: 0x%.4x\n", ntohs(icmp_protocol->identification));
	printf("Sequence: 0x%.4x\n", ntohs(icmp_protocol->sequence));
}

/* ARP 处理 */
void arp_protocol_packet_handler(
	u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data
) {

	struct arp_header *arp_protocol;

	u_short protocol_type;
	u_short hardware_type;
	u_short operation_code;
	u_char hardware_length;
	u_char protocol_length;

	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

	arp_protocol = (struct arp_header*)(pkt_data + 14);

	/*hardware_type = ntohs(arp_protocol->hardware_type);
	protocol_type = ntohs(arp_protocol->protocol_type);
	operation_code = ntohs(arp_protocol->operation_code);
	hardware_length = arp_protocol->hardware_length;
	protocol_length = arp_protocol->protocol_length;

	printf("%d%s", protocol_length, timestr);*/

	printf("==================ARP 协议==================\n");
	printf("硬件类型");
	switch (ntohs(arp_protocol->hardware_type))
	{
	case 1:
		printf("以太网");
		break;
	default:
		break;
	}
	printf(" (%d)\n", ntohs(arp_protocol->hardware_type));
	printf("协议类型\n");
	switch (ntohs(arp_protocol->protocol_type))
	{
	case 1:
		printf("ARP请求协议\n");
		break;
	case 2:
		printf("ARP应答协议\n");
		break;
	case 3:
		printf("RARP请求协议\n");
		break;
	case 4:
		printf("RARP应答协议\n");
		break;
	default:
		printf("未知协议");
		break;
	}
}

/* IP 处理，已用于MFC */
void CWinPcapBeta20Dlg::ip_protocol_packet_handler(
	u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data
) {

	ip_header *ih;
	u_int header_length;	// 首部长度 版本
	u_char tos;				//服务质量
	u_short checksum;		//校验和
	ip_address saddr;		//源IP地址
	ip_address daddr;		//目的IP地址
	u_char ttl;				//生命周期
	u_short tlen;			//总长度
	u_short identification; //身份识别
	u_short offset;			//分组偏移

	CString str, temp_str;

	/*
	* 未使用变量
	*/
	(VOID)(param);

	// printf("===========IP Protocol===========\n");

	ih = (ip_header *)(pkt_data + 14);
	header_length = (ih->ver_ihl & 0xf) * 4;
	checksum = ntohs(ih->crc);
	tos = ih->tos;
	offset = ntohs(ih->flags_fo);

	saddr = ih->saddr;
	daddr = ih->daddr;
	ttl = ih->ttl;
	identification = ih->identification;
	tlen = ih->tlen;
	offset = ih->flags_fo;

	/* 获取并显示IP地址 */
	str = "";
	temp_str.Format(_T("%d.%d.%d.%d"),
		saddr.byte1,
		saddr.byte2,
		saddr.byte3,
		saddr.byte4);
	str += temp_str;
	temp_str.Format(_T("%d.%d.%d.%d"),
		daddr.byte1,
		daddr.byte2,
		daddr.byte3,
		daddr.byte4);
	str += "->";
	str += temp_str;
	list.SetItemText(row, 5, str);

	// printf("版本号:%d\n", ih->ip_version);
	/*printf("首部长度:%d\n", header_length);
	printf("服务质量:%d\n", tos);
	printf("总长度:%d\n", ntohs(tlen));
	printf("标识:%d\n", ntohs(ih->identification));
	printf("偏移:%d\n", (offset & 0x1fff) * 8);
	printf("生存时间:%d\n", ttl);
	printf("协议类型:%d\n", ih->proto);*/

	switch (ih->proto) {
	case 6:
		// tcp_protocol_packet_handler(param, header, pkt_data);
		temp_str = "TCP";
		break;
	case 17:
		// udp_protocol_packet_handler(param, header, pkt_data);
		temp_str = "UDP";
		break;
	case 1:
		// icmp_protocol_packet_handler(param, header, pkt_data);
		temp_str = "ICMP";
		break;
	default:
		break;
	}
	/* 获取显示IP协议PCI信息 */
	str.Format(_T("首部长度: %d; 服务质量: %d; 总长度: %d; 标识: %d; 偏移: %d; 生存时间: %d; 协议类型: "), 
		header_length,
		tos,
		ntohs(tlen),
		ntohs(ih->identification),
		(offset & 0x1fff) * 8,
		ttl);
	str += temp_str;
	list.SetItemText(row, 6, str);
}

/* 以太网处理，已用于MFC */
void CWinPcapBeta20Dlg::ethernet_protocol_packet_handler(
	u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data
) {
	u_short ethernet_type;					// 以太网类型
	ether_header *ethernet_protocol;        // 以太网协议
	u_char *mac_string;						// 以太网地址
	CString str, temp_str;

	str = "Ethernet";
	list.SetItemText(row, 3, str);
	ethernet_protocol = (struct ether_header*)pkt_data;      // 获取以太网数据内容
	ethernet_type = ntohs(ethernet_protocol->ether_type);    // 获取以太网类型

	/* 判断以太网类型 */
	switch (ethernet_type) {
	case 0x0800:
		str = "IP";
		list.SetItemText(row, 3, str);
		break;
	case 0x0835:
		str = "RARP";
		list.SetItemText(row, 3, str);
		break;
	case 0x0806:
		str = "ARP";
		list.SetItemText(row, 3, str);
		break;
	default:
		str = "Unknown";
		list.SetItemText(row, 3, str);
		break;
	}

	// 获取以太网源地址
	mac_string = ethernet_protocol->ether_shost;
	str = "";
	temp_str.Format(_T("%02x:%02x:%02x:%02x:%02x:%02x"),
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));
	str += temp_str;
	/*printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5)
	);*/

	// 获取以太网目的地址
	mac_string = ethernet_protocol->ether_dhost;
	temp_str.Format(_T("%02x:%02x:%02x:%02x:%02x:%02x"),
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));
	str += "->";
	str += temp_str;
	list.SetItemText(row, 4, str);

	/* 进入下一层协议 */
	switch (ethernet_type) {
	case 0x0800:
		ip_protocol_packet_handler(param, header, pkt_data);
		break;
	case 0x0806:
		arp_protocol_packet_handler(param, header, pkt_data);
		break;
	default:
		break;
	}
}

void CWinPcapBeta20Dlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnOK();
}

void CWinPcapBeta20Dlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnCancel();
}

void CWinPcapBeta20Dlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}

/* 主要处理函数，点击开始捕获按钮后执行，可以修改捕获数目之后重新捕获 */
void CWinPcapBeta20Dlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	
	while (list.DeleteColumn(0));

	max_count = 10;
	if (GetDlgItemInt(IDC_EDIT1))
		max_count = GetDlgItemInt(IDC_EDIT1);

	/* 获得设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		MessageBox(L"寻找设备出错，请确认WinPcap正确安装，并重新启动应用", L"警告", MB_OK);
		exit(1);
	}

	/* 设定设备列表 */
	i = 0;
	for (d = alldevs; d; d = d->next) {
		++i;
	}

	if (i == 0)
	{
		MessageBox(L"没有找到设备，请确保WinPcap已正确安装，并重新启动应用", L"警告", MB_OK);
		return;
	}

	while (1) {
		inum = GetDlgItemInt(IDC_EDIT2);
		// if (inum > 0 && inum <= i)
		if (inum == 6)
			break;
		else {
			MessageBox(L"编号超出范围，请重新输入", L"警告", MB_OK);
			return;
		}
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, ++i);

	/* 打开适配器 */
	if ((adhandle = pcap_open(
		d->name,	// 设备名
		65536,		// 要捕捉的数据包的部分 
					// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,      // 混杂模式（1）
		1000,							// 读取超时时间
		NULL,							// 远程机器验证
		errbuf							// 错误缓冲池
	)) == NULL)
	{
		MessageBox(L"无法打开设备，请尝试重启应用", L"警告", MB_OK);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return;
	}

	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		MessageBox(L"抱歉，该程序只考虑以太网！", L"警告", MB_OK);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		MessageBox(L"编译过滤器失败！", L"警告", MB_OK);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		MessageBox(L"设置过滤器失败！", L"警告", MB_OK);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return;
	}

	CString str, temp_str;
	str = "正在监听设备:";
	str += d->description;
	MessageBox(str, L"提示", MB_OK);

	list.DeleteAllItems();
	while (list.DeleteColumn(0));
	count = 1;
	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	CRect rect;
	list.GetClientRect(&rect);
	list.InsertColumn(0, _T("包编号"), LVCFMT_CENTER, rect.Width() / 12 , 0);
	list.InsertColumn(1, _T("时间"), LVCFMT_CENTER, rect.Width() / 12, 0);
	list.InsertColumn(2, _T("包长度"), LVCFMT_CENTER, rect.Width() / 12, 0);
	list.InsertColumn(3, _T("协议类型"), LVCFMT_CENTER, rect.Width() / 12, 0);
	list.InsertColumn(4, _T("MAC地址"), LVCFMT_CENTER, rect.Width() / 2, 0);
	list.InsertColumn(5, _T("IP地址"), LVCFMT_CENTER, rect.Width() / 2, 0);
	list.InsertColumn(6, _T("IP信息"), LVCFMT_CENTER, rect.Width(), 0);

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (count > max_count)
			break;

		if (res == 0)
			/* 超时时间到 */
			continue;

		//将时间戳转化为可识别格式
		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

		//输出编号、时间戳和包长度
		// printf("No.%d\ttime: %s\tlen: %ld\n", count++, timestr, header->len);
		str.Format(_T("%d"), count++);
		row = list.InsertItem(count, str);
		str = "";
		str += timestr;
		list.SetItemText(row, 1, str);
		str.Format(_T("%ld"), header->len);
		list.SetItemText(row, 2, str);

		//char temp[LINE_LEN + 1];
		////输出包内容 未在MFC界面实现
		//for (i = 0; i < header->caplen; ++i)
		//{
		//	printf("%.2x ", pkt_data[i]);
		//	if (isgraph(pkt_data[i]) || pkt_data[i] == ' ')
		//		temp[i % LINE_LEN] = pkt_data[i];
		//	else
		//		temp[i % LINE_LEN] = '.';

		//	if (i % LINE_LEN == 15)
		//	{
		//		temp[16] = '\0';
		//		printf("        ");
		//		printf("%s", temp);
		//		printf("\n");
		//		memset(temp, 0, LINE_LEN);
		//	}
		//}
		//printf("\n");

		// 分析数据包
		ethernet_protocol_packet_handler(NULL, header, pkt_data);
	 }

	if (res == -1) {
		MessageBox(L"获取数据包信息失败！", L"警告", MB_OK);
		pcap_freealldevs(alldevs);
		return;
	}
}

void CWinPcapBeta20Dlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	max_count = max_count + 1;
}

void CWinPcapBeta20Dlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}

void CWinPcapBeta20Dlg::OnEnChangeEdit2()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}