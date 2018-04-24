
// WinPcapBeta2.0Dlg.cpp : ʵ���ļ�
// �Զ����ɵĺ������������ұ�д�Ĳ���
// �����ŷ��ͬ���޸�ʱע������

#include "stdafx.h"
#include "Resource.h"
#include "WinPcapBeta2.0.h"
#include "WinPcapBeta2.0Dlg.h"
#include "afxdialogex.h"
#include "pcap.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/* ����������������ݵĳ��� */
// #define LINE_LEN 16
// #define MAX_ADDR_LEN 16

/* ����ȫ�ֱ��� */
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

/* �Զ����ɵĺ�����δ���޸ģ� */
// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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

// CWinPcapBeta20Dlg �Ի���
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

/* CWinPcapBeta20Dlg ��Ϣ�������������Ӧ�����ʼ��*/
BOOL CWinPcapBeta20Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	CString str;
	CRect rect;
	list.GetClientRect(&rect);
	list.InsertColumn(0, _T("�豸���"), LVCFMT_CENTER, rect.Width() / 5, 0);
	list.InsertColumn(1, _T("�豸����"), LVCFMT_CENTER, rect.Width() / (5 / 2), 0);
	list.InsertColumn(2, _T("�豸����"), LVCFMT_CENTER, rect.Width() / (5 / 2), 0);

	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		MessageBox(L"Ѱ���豸������ȷ��WinPcap��ȷ��װ������������Ӧ��", L"����", MB_OK);
		exit(1);
	}

	/* ��ʾ�豸�б� */
	for (d = alldevs; d; d = d->next) {
		str.Format(_T("%d"), ++i);
		int row = list.InsertItem(i, str);
		// list.SetItemText(row, 0, str);
		str = d->name;
		list.SetItemText(row, 1, str);
		str = d->description;
		list.SetItemText(row, 2, str);
	}

	/* δ�ҵ��豸���� */
	if (i == 0) {
		MessageBox(L"û���ҵ��豸����ȷ��WinPcap����ȷ��װ������������Ӧ��", L"����", MB_OK);
		return FALSE;
	}

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CWinPcapBeta20Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù����ʾ��
HCURSOR CWinPcapBeta20Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/* �����������Լ���д��ĿǰֻMFC����Ӧ����Ethernet��IP */
/* TCP ���� */
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

/* UDP ���� */
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

/* ICMP ���� */
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
		printf("(request)\n"); // ����������
		break;
	case 0:
		printf("(reply)\n"); // ����Ӧ����
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

/* ARP ���� */
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

	printf("==================ARP Э��==================\n");
	printf("Ӳ������");
	switch (ntohs(arp_protocol->hardware_type))
	{
	case 1:
		printf("��̫��");
		break;
	default:
		break;
	}
	printf(" (%d)\n", ntohs(arp_protocol->hardware_type));
	printf("Э������\n");
	switch (ntohs(arp_protocol->protocol_type))
	{
	case 1:
		printf("ARP����Э��\n");
		break;
	case 2:
		printf("ARPӦ��Э��\n");
		break;
	case 3:
		printf("RARP����Э��\n");
		break;
	case 4:
		printf("RARPӦ��Э��\n");
		break;
	default:
		printf("δ֪Э��");
		break;
	}
}

/* IP ����������MFC */
void CWinPcapBeta20Dlg::ip_protocol_packet_handler(
	u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data
) {

	ip_header *ih;
	u_int header_length;	// �ײ����� �汾
	u_char tos;				//��������
	u_short checksum;		//У���
	ip_address saddr;		//ԴIP��ַ
	ip_address daddr;		//Ŀ��IP��ַ
	u_char ttl;				//��������
	u_short tlen;			//�ܳ���
	u_short identification; //���ʶ��
	u_short offset;			//����ƫ��

	CString str, temp_str;

	/*
	* δʹ�ñ���
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

	/* ��ȡ����ʾIP��ַ */
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

	// printf("�汾��:%d\n", ih->ip_version);
	/*printf("�ײ�����:%d\n", header_length);
	printf("��������:%d\n", tos);
	printf("�ܳ���:%d\n", ntohs(tlen));
	printf("��ʶ:%d\n", ntohs(ih->identification));
	printf("ƫ��:%d\n", (offset & 0x1fff) * 8);
	printf("����ʱ��:%d\n", ttl);
	printf("Э������:%d\n", ih->proto);*/

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
	/* ��ȡ��ʾIPЭ��PCI��Ϣ */
	str.Format(_T("�ײ�����: %d; ��������: %d; �ܳ���: %d; ��ʶ: %d; ƫ��: %d; ����ʱ��: %d; Э������: "), 
		header_length,
		tos,
		ntohs(tlen),
		ntohs(ih->identification),
		(offset & 0x1fff) * 8,
		ttl);
	str += temp_str;
	list.SetItemText(row, 6, str);
}

/* ��̫������������MFC */
void CWinPcapBeta20Dlg::ethernet_protocol_packet_handler(
	u_char *param,
	const struct pcap_pkthdr *header,
	const u_char *pkt_data
) {
	u_short ethernet_type;					// ��̫������
	ether_header *ethernet_protocol;        // ��̫��Э��
	u_char *mac_string;						// ��̫����ַ
	CString str, temp_str;

	str = "Ethernet";
	list.SetItemText(row, 3, str);
	ethernet_protocol = (struct ether_header*)pkt_data;      // ��ȡ��̫����������
	ethernet_type = ntohs(ethernet_protocol->ether_type);    // ��ȡ��̫������

	/* �ж���̫������ */
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

	// ��ȡ��̫��Դ��ַ
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

	// ��ȡ��̫��Ŀ�ĵ�ַ
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

	/* ������һ��Э�� */
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
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CDialogEx::OnOK();
}

void CWinPcapBeta20Dlg::OnBnClickedCancel()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CDialogEx::OnCancel();
}

void CWinPcapBeta20Dlg::OnEnChangeEdit1()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}

/* ��Ҫ�������������ʼ����ť��ִ�У������޸Ĳ�����Ŀ֮�����²��� */
void CWinPcapBeta20Dlg::OnBnClickedButton1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	
	while (list.DeleteColumn(0));

	max_count = 10;
	if (GetDlgItemInt(IDC_EDIT1))
		max_count = GetDlgItemInt(IDC_EDIT1);

	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		MessageBox(L"Ѱ���豸������ȷ��WinPcap��ȷ��װ������������Ӧ��", L"����", MB_OK);
		exit(1);
	}

	/* �趨�豸�б� */
	i = 0;
	for (d = alldevs; d; d = d->next) {
		++i;
	}

	if (i == 0)
	{
		MessageBox(L"û���ҵ��豸����ȷ��WinPcap����ȷ��װ������������Ӧ��", L"����", MB_OK);
		return;
	}

	while (1) {
		inum = GetDlgItemInt(IDC_EDIT2);
		// if (inum > 0 && inum <= i)
		if (inum == 6)
			break;
		else {
			MessageBox(L"��ų�����Χ������������", L"����", MB_OK);
			return;
		}
	}

	/* ��ת����ѡ�豸 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, ++i);

	/* �������� */
	if ((adhandle = pcap_open(
		d->name,	// �豸��
		65536,		// Ҫ��׽�����ݰ��Ĳ��� 
					// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,      // ����ģʽ��1��
		1000,							// ��ȡ��ʱʱ��
		NULL,							// Զ�̻�����֤
		errbuf							// ���󻺳��
	)) == NULL)
	{
		MessageBox(L"�޷����豸���볢������Ӧ��", L"����", MB_OK);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return;
	}

	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		MessageBox(L"��Ǹ���ó���ֻ������̫����", L"����", MB_OK);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return;
	}

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		MessageBox(L"���������ʧ�ܣ�", L"����", MB_OK);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		MessageBox(L"���ù�����ʧ�ܣ�", L"����", MB_OK);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return;
	}

	CString str, temp_str;
	str = "���ڼ����豸:";
	str += d->description;
	MessageBox(str, L"��ʾ", MB_OK);

	list.DeleteAllItems();
	while (list.DeleteColumn(0));
	count = 1;
	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	CRect rect;
	list.GetClientRect(&rect);
	list.InsertColumn(0, _T("�����"), LVCFMT_CENTER, rect.Width() / 12 , 0);
	list.InsertColumn(1, _T("ʱ��"), LVCFMT_CENTER, rect.Width() / 12, 0);
	list.InsertColumn(2, _T("������"), LVCFMT_CENTER, rect.Width() / 12, 0);
	list.InsertColumn(3, _T("Э������"), LVCFMT_CENTER, rect.Width() / 12, 0);
	list.InsertColumn(4, _T("MAC��ַ"), LVCFMT_CENTER, rect.Width() / 2, 0);
	list.InsertColumn(5, _T("IP��ַ"), LVCFMT_CENTER, rect.Width() / 2, 0);
	list.InsertColumn(6, _T("IP��Ϣ"), LVCFMT_CENTER, rect.Width(), 0);

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (count > max_count)
			break;

		if (res == 0)
			/* ��ʱʱ�䵽 */
			continue;

		//��ʱ���ת��Ϊ��ʶ���ʽ
		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

		//�����š�ʱ����Ͱ�����
		// printf("No.%d\ttime: %s\tlen: %ld\n", count++, timestr, header->len);
		str.Format(_T("%d"), count++);
		row = list.InsertItem(count, str);
		str = "";
		str += timestr;
		list.SetItemText(row, 1, str);
		str.Format(_T("%ld"), header->len);
		list.SetItemText(row, 2, str);

		//char temp[LINE_LEN + 1];
		////��������� δ��MFC����ʵ��
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

		// �������ݰ�
		ethernet_protocol_packet_handler(NULL, header, pkt_data);
	 }

	if (res == -1) {
		MessageBox(L"��ȡ���ݰ���Ϣʧ�ܣ�", L"����", MB_OK);
		pcap_freealldevs(alldevs);
		return;
	}
}

void CWinPcapBeta20Dlg::OnBnClickedButton2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	max_count = max_count + 1;
}

void CWinPcapBeta20Dlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	*pResult = 0;
}

void CWinPcapBeta20Dlg::OnEnChangeEdit2()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
}