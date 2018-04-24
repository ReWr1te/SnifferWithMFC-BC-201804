
// WinPcapBeta2.0Dlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"


// CWinPcapBeta20Dlg 对话框
class CWinPcapBeta20Dlg : public CDialogEx
{
// 构造
public:
	CWinPcapBeta20Dlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WINPCAPBETA20_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnEnChangeEdit1();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	CListCtrl list;
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnEnChangeEdit2();
	afx_msg void ethernet_protocol_packet_handler(
		u_char *param,
		const struct pcap_pkthdr *header,
		const u_char *pkt_data
	);
	afx_msg void ip_protocol_packet_handler(
		u_char *param,
		const struct pcap_pkthdr *header,
		const u_char *pkt_data
	);
};


/* 以太网协议格式 */
typedef struct ether_header {
	u_char ether_dhost[6];		// 目的MAC地址
	u_char ether_shost[6];      // 源MAC地址
	u_short ether_type;         // 以太网协议类型
}ether_header;

/* 4字节的IP地址 */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header {
	u_char  ver_ihl;		// 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 服务类型(Type of service) 
	u_short tlen;           // 总长(Total length) 
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)
	u_char  proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address  saddr;      // 源地址(Source address)
	ip_address  daddr;      // 目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* TCP 首部 */
typedef struct tcp_header {
	u_short sport;          //源端口
	u_short dport;          //目的端口
	u_int sequence;         // 序列码
	u_int ack;              // 回复码

#ifdef WORDS_BIGENDIAN
	u_char offset : 4, reserved : 4;   // 偏移 预留
#else
	u_char reserved : 4, offset : 4;   // 预留 偏移
#endif

	u_char flags;           // 标志
	u_short windows;        // 窗口大小
	u_short checksum;		// 校验和
	u_short urgent_pointer; // 紧急指针
}tcp_header;

/* UDP 首部*/
typedef struct udp_header {
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP数据包长度(Datagram length)
	u_short crc;            // 校验和(Checksum)
}udp_header;

/* ICMP 首部 */
typedef struct icmp_header {
	u_char type;				// ICMP类型
	u_char code;				// 代码
	u_short checksum;			// 校验和
	u_short identification;		// 标识
	u_short sequence;			// 序列号
	u_long timestamp;			// 时间戳
}icmp_header;

/* ARP 首部 */
typedef struct arp_header {
	u_short hardware_type;					// 格式化的硬件地址
	u_short protocol_type;					// 协议地址格式
	u_char hardware_length;					// 硬件地址长度
	u_char protocol_length;					// 协议地址长度
	u_short operation_code;					// 操作码
	u_char source_ethernet_address[6];		// 发送者硬件地址
	u_char source_ip_address[4];			// 发送者协议地址
	u_char destination_ethernet_address[6];	// 目的方硬件地址
	u_char destination_ip_address[4];		// 目的方协议地址
}arp_header;