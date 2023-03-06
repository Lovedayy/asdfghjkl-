
// NetCaptureDlg.h: 头文件
//

#pragma once
#include"pcap.h"
#include"header.h"
#include"analyze.h"

// CNetCaptureDlg 对话框
class CNetCaptureDlg : public CDialogEx
{
// 构造
public:
	CNetCaptureDlg(CWnd* pParent = nullptr);	// 标准构造函数

	/* 实现功能funcs */
	bool initCap(); //初始化
	int start();
	void OnNMCustomdrawList2(NMHDR* pNMHDR, LRESULT* pResult);
	//开始抓包
	int updateTree(int index);
	int updateEdit(int index);
	int savefile();
	int readfile(CString fpath);
	bool iprecombine(int index);//重组
	int updateTree1(pkt_T* pakeage_T, int len); //展示重组树
	int updateEdit1(int len, u_char* pkt_data); //展示重组详细
	bool search(u_char* str);

	/* data */
	char errbuf[PCAP_ERRBUF_SIZE];//内置errorbuf
	int n_dev;				//网卡数
	pcap_if_t* alldev;		//所有网卡
	pcap_if_t* dev;			//选定的网卡
	pcap_t* handle; //pcap 创建的【捕获句柄】
	CString filter;			//filter
	int n_pkt;				    //抓包数
	struct pktcount pkcount_T;	// 各类包计数结构体

	pcap_dumper_t* myfile;//存储的文件
	char filepath[512];
	char filename[512];

	CPtrList pk_list;			//抓包链表
	CPtrList m_localDataList;	//pkt_T链表，存储规范化网络包
	CPtrList m_netDataList;		//char*链表，存储网络包数据

	HANDLE m_threadhandle; //线程


// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_NETCAPTURE_DIALOG };
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

private:
	int cursor_index = -1;
public:
	afx_msg void OnEnChangeEdit5();
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
	CTreeCtrl m_tree1;
	CListCtrl m_list1;
	afx_msg void OnBnClickedBtStart();
	void initAll(); //对窗口初始化
	void initNetSelector();
	afx_msg void OnClickedBtnStart();
	afx_msg void OnClickedBtnStop();
	void OnFilter();
	CEdit m_edit1;
	CComboBox m_selector;
	CButton m_BtStart;
	CButton m_BtStop;
	CString m_tcpnum;
	CString m_udpnum;
	CString m_arpnum;
	CString m_icmpnum;
	CString m_httpnum;
	CString m_dnsnum;
	CString m_totalnum;
	afx_msg void OnEnChangeEdit8();
	afx_msg void OnBnClickedBtStop();
	afx_msg void OnTvnSelchangedTree1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCbnSelchangeCombo1();
//	afx_msg void OnLvnItemchangingList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedBtYes();
	CButton m_BtSave;
	CButton m_BtYes;
	afx_msg void OnNMCustomdrawList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedBtSave();
};
