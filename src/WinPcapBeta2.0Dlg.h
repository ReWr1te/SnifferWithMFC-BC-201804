
// WinPcapBeta2.0Dlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"


// CWinPcapBeta20Dlg �Ի���
class CWinPcapBeta20Dlg : public CDialogEx
{
// ����
public:
	CWinPcapBeta20Dlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WINPCAPBETA20_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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


/* ��̫��Э���ʽ */
typedef struct ether_header {
	u_char ether_dhost[6];		// Ŀ��MAC��ַ
	u_char ether_shost[6];      // ԴMAC��ַ
	u_short ether_type;         // ��̫��Э������
}ether_header;

/* 4�ֽڵ�IP��ַ */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 �ײ� */
typedef struct ip_header {
	u_char  ver_ihl;		// �汾 (4 bits) + �ײ����� (4 bits)
	u_char  tos;            // ��������(Type of service) 
	u_short tlen;           // �ܳ�(Total length) 
	u_short identification; // ��ʶ(Identification)
	u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	u_char  ttl;            // ���ʱ��(Time to live)
	u_char  proto;          // Э��(Protocol)
	u_short crc;            // �ײ�У���(Header checksum)
	ip_address  saddr;      // Դ��ַ(Source address)
	ip_address  daddr;      // Ŀ�ĵ�ַ(Destination address)
	u_int   op_pad;         // ѡ�������(Option + Padding)
}ip_header;

/* TCP �ײ� */
typedef struct tcp_header {
	u_short sport;          //Դ�˿�
	u_short dport;          //Ŀ�Ķ˿�
	u_int sequence;         // ������
	u_int ack;              // �ظ���

#ifdef WORDS_BIGENDIAN
	u_char offset : 4, reserved : 4;   // ƫ�� Ԥ��
#else
	u_char reserved : 4, offset : 4;   // Ԥ�� ƫ��
#endif

	u_char flags;           // ��־
	u_short windows;        // ���ڴ�С
	u_short checksum;		// У���
	u_short urgent_pointer; // ����ָ��
}tcp_header;

/* UDP �ײ�*/
typedef struct udp_header {
	u_short sport;          // Դ�˿�(Source port)
	u_short dport;          // Ŀ�Ķ˿�(Destination port)
	u_short len;            // UDP���ݰ�����(Datagram length)
	u_short crc;            // У���(Checksum)
}udp_header;

/* ICMP �ײ� */
typedef struct icmp_header {
	u_char type;				// ICMP����
	u_char code;				// ����
	u_short checksum;			// У���
	u_short identification;		// ��ʶ
	u_short sequence;			// ���к�
	u_long timestamp;			// ʱ���
}icmp_header;

/* ARP �ײ� */
typedef struct arp_header {
	u_short hardware_type;					// ��ʽ����Ӳ����ַ
	u_short protocol_type;					// Э���ַ��ʽ
	u_char hardware_length;					// Ӳ����ַ����
	u_char protocol_length;					// Э���ַ����
	u_short operation_code;					// ������
	u_char source_ethernet_address[6];		// ������Ӳ����ַ
	u_char source_ip_address[4];			// ������Э���ַ
	u_char destination_ethernet_address[6];	// Ŀ�ķ�Ӳ����ַ
	u_char destination_ip_address[4];		// Ŀ�ķ�Э���ַ
}arp_header;