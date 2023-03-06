
// NetCaptureDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "NetCapture.h"
#include "NetCaptureDlg.h"
#include "afxdialogex.h"
#include "mstcpip.h"//加入tcpip头文件
#include "CFilterDlg.h"
#include "header.h"
using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CString mMsg;
SOCKET rawSocket;
CString netIp;
#define WM_MSG  (WM_USER+101)
#define MAXPACKETLEN 500  //定义最大接收报文数目
char buff[MAXPACKETLEN + 1][4096];
int packetLengths[MAXPACKETLEN + 2];
struct pkt_T* FindFstIp(struct pkt_T* tmp, int& index, LPVOID lpParameter);


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


// CNetCaptureDlg 对话框


//构造函数
CNetCaptureDlg::CNetCaptureDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_NETCAPTURE_DIALOG, pParent)
	, m_tcpnum(_T(""))
	, m_arpnum(_T(""))
	, m_icmpnum(_T(""))
	, m_httpnum(_T(""))
	, m_dnsnum(_T(""))
	, m_totalnum(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

//DoDataExchange是一个MFC框架中的虚函数，用于数据交换
//用于将控件中的数据与对话框类中的变量进行交换
//当MFC框架在运行对话框时，会在初始化对话框时自动调用 DoDataExchange 函数
//在这个函数中，我们可以指定对话框中的控件与类中的变量之间的数据交换方式
//通常我们使用 DDX_ 函数（Data Exchange Functions）来实现这个过程。
void CNetCaptureDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TREE1, m_tree1);
	DDX_Control(pDX, IDC_LIST1, m_list1);
	DDX_Control(pDX, IDC_EDIT1, m_edit1);
	DDX_Control(pDX, IDC_COMBO1, m_selector);
	DDX_Control(pDX, IDC_BUTTON1, m_BtStart);
	DDX_Control(pDX, IDC_BUTTON2, m_BtStop);
	//当用户输入一个字符串时，DoDataExchange 函数将该字符串存储到 m_tcpnum 变量中：
	DDX_Text(pDX, IDC_EDIT2, m_tcpnum);
	DDX_Text(pDX, IDC_EDIT3, m_udpnum);
	DDX_Text(pDX, IDC_EDIT4, m_arpnum);
	DDX_Text(pDX, IDC_EDIT5, m_icmpnum);
	DDX_Text(pDX, IDC_EDIT6, m_httpnum);
	DDX_Text(pDX, IDC_EDIT7, m_dnsnum);
	DDX_Text(pDX, IDC_EDIT8, m_totalnum);
	DDX_Control(pDX, IDC_BUTTON3, m_BtSave);
}

//BEGIN_MESSAGE_MAP 是 MFC 框架中的一个宏，用于设置消息映射表
//它定义了如何将特定的消息（例如 WM_COMMAND、WM_PAINT 等）与处理它们的类成员函数联系起来
//BEGIN_MESSAGE_MAP 宏会生成一个类似于 switch - case 的代码块
//根据不同的消息类型调用不同的消息处理函数。
BEGIN_MESSAGE_MAP(CNetCaptureDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	//当接收到一个 WM_PAINT 消息时，会调用 CNetCaptureDlg 类的 OnPaint 成员函数来处理这个消息。
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()

	ON_EN_CHANGE(IDC_EDIT5, &CNetCaptureDlg::OnEnChangeEdit5)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CNetCaptureDlg::OnLvnItemchangedList1)
	ON_BN_CLICKED(IDC_BUTTON1, &CNetCaptureDlg::OnBnClickedBtStart)
	ON_EN_CHANGE(IDC_EDIT8, &CNetCaptureDlg::OnEnChangeEdit8)
	ON_BN_CLICKED(IDC_BUTTON2, &CNetCaptureDlg::OnBnClickedBtStop)
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE1, &CNetCaptureDlg::OnTvnSelchangedTree1)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CNetCaptureDlg::OnCbnSelchangeCombo1)
//	ON_NOTIFY(LVN_ITEMCHANGING, IDC_LIST1, &CNetCaptureDlg::OnLvnItemchangingList1)
	ON_BN_CLICKED(IDC_BUTTON3, &CNetCaptureDlg::OnBnClickedBtYes)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CNetCaptureDlg::OnNMCustomdrawList1)
	ON_BN_CLICKED(IDC_BUTTON4, &CNetCaptureDlg::OnBnClickedBtSave)
END_MESSAGE_MAP()


// CNetCaptureDlg 消息处理程序

BOOL CNetCaptureDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		// 获取字符串资源 IDS_ABOUTBOX 并将其加载到 strAboutMenu 变量中
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			// 在系统菜单中添加“strAboutMenu”菜单项
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	initAll(); //对窗口初始化

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CNetCaptureDlg::initAll() {

	m_list1.SetExtendedStyle(m_list1.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);// 为列表视图控件添加全行选中和栅格风格
	m_list1.InsertColumn(0, _T("序号"), LVCFMT_CENTER, 50);
	m_list1.InsertColumn(1, _T("时间"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(2, _T("源MAC地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(3, _T("目的MAC地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(4, _T("长度"), LVCFMT_CENTER, 50);
	m_list1.InsertColumn(5, _T("协议"), LVCFMT_CENTER, 70);
	m_list1.InsertColumn(6, _T("源IP地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(7, _T("目的IP地址"), LVCFMT_CENTER, 120);

	/*初始化接口列表*/
	m_selector.AddString(_T("选择你要抓包的网卡吧！"));
	for (dev = alldev; dev; dev = dev->next)
	{
		if (dev->description)
			m_selector.AddString(CString(dev->description));
	}
	m_selector.SetCurSel(0);
	m_BtStop.EnableWindow(FALSE);
	m_BtSave.EnableWindow(FALSE);

	UpdateData(true);
}

//该函数用于处理系统命令事件，比如最小化窗口、关闭窗口等
void CNetCaptureDlg::OnSysCommand(UINT nID, LPARAM lParam)
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
//  这将由框架自动完成CSnifferDlg::OnInitDialog()

void CNetCaptureDlg::OnPaint()
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

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CNetCaptureDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//开始抓包按钮
void CNetCaptureDlg::OnClickedBtnStart()
{
	// TODO: 在此添加控件通知处理程序代码
	/* 是否保存上次抓包数据 */
	if (!this->m_localDataList.IsEmpty())
	{
		if (MessageBox(_T("是否存储当前抓包数据？"), _T("警告"), MB_YESNO) == IDYES)
			this->savefile();
	}
	/* init */
	this->n_pkt = 0; //重新计数
	this->m_localDataList.RemoveAll(); //列表清空
	this->m_netDataList.RemoveAll();
	memset(&(this->pkcount_T), 0, sizeof(struct pktcount));
	/* 开始抓包 */
	if (this->start() == -1)
		return;//异常在start里已经处理 这里不处理
	/* 清除 */
	this->m_list1.DeleteAllItems();
	this->m_tree1.DeleteAllItems();
	this->m_edit1.SetWindowTextW(_T(""));
	this->m_BtStart.EnableWindow(FALSE);//禁止重复开始
	this->m_BtStop.EnableWindow(TRUE);//停止按钮解锁
	this->m_BtSave.EnableWindow(FALSE);//禁止保存
}

//停止抓包按钮
void CNetCaptureDlg::OnClickedBtnStop()
{
	// TODO: 在此添加控件通知处理程序代码
	/* 没有线程不需要处理 */
	if (this->m_threadhandle == NULL)
		return;
	/* 关闭线程，异常处理 */
	if (handle)
		pcap_close(handle);
	if (TerminateThread(this->m_threadhandle, -1) == 0)
	{
		MessageBox(_T("错误：关闭线程失败"));
		return;
	}
	this->m_threadhandle = NULL;
	/* 处理按钮 */
	this->m_BtStart.EnableWindow(TRUE);//开始允许
	this->m_BtStop.EnableWindow(FALSE);//禁止两次停止
	this->m_BtSave.EnableWindow(TRUE);//可保存
}

//确认过滤器
void CNetCaptureDlg::OnBnClickedBtYes()
{
	// TODO: 在此添加控件通知处理程序代码
	GetDlgItem(IDC_EDIT2)->GetWindowTextW(this->filter);
}

//保存包按钮
void CNetCaptureDlg::OnBnClickedBtSave()
{
	// TODO: 在此添加控件通知处理程序代码
	/* 调用定义的保存函数保存 */
	if (this->savefile() < 0)
		return;
}

//当用户点击某个数据包时，先判断这个数据包在列表中是否存在，如果不存在则直接返回。
//如果存在，则获取该数据包在列表中的索引，并更新界面上的详细信息和展示该数据包的内容。
//最后，树形结构中的节点会被自动展开以显示所有相关内容。
void CNetCaptureDlg::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	/* 如果光标选择的包不在存储列表 */
	int n;
	n = this->m_list1.GetHotItem();
	if (n >= this->m_localDataList.GetCount() || n == -1)
		return;

	/* 更新详细 和 展示包内容 */
	cursor_index = n;
	this->updateEdit(n);
	this->updateTree(n);
	/*自动展开树*/
	//树形结构展开是通过 CTreeCtrl 类的 Expand 函数实现的。
	//该函数可以根据指定的标志将一个树形结构的节点展开或折叠，
	//可以展开单个节点、所有子节点或所有节点。
	HTREEITEM tmp = this->m_tree1.GetRootItem();
	this->m_tree1.Expand(tmp, TVE_EXPAND);
	tmp = this->m_tree1.GetNextItem(tmp, TVGN_CHILD);
	while (tmp)
	{
		this->m_tree1.Expand(tmp, TVE_EXPAND);
		tmp = this->m_tree1.GetNextItem(tmp, TVGN_NEXT);
	}
	*pResult = 0;
}


// 从 TCP 数据包中提取 HTTP 报文头信息并赋值给 http_header 变量
void parseHttpHeader(unsigned char* buffer, int size, httphdr& http_header) {
	char* http_data = (char*)buffer;
	int offset = 0;

	// 初始化 HTTP 报文头结构体
	memset(&http_header, 0, sizeof(http_header));

	// 从 HTTP 报文中逐一提取信息并赋值给结构体相应字段
	while (offset < size) {
		if (memcmp(&http_data[offset], "GET ", 4) == 0 || memcmp(&http_data[offset], "POST", 4) == 0) {
			strncpy_s(http_header.method, &http_data[offset], 15);
			offset += 4;
		}
		else if (memcmp(&http_data[offset], "Host:", 5) == 0) {
			strncpy_s(http_header.host, &http_data[offset + 6], 127);
			offset += 6;
		}
		else if (memcmp(&http_data[offset], "Referer:", 8) == 0) {
			// skip this field
			offset += 8;
		}
		else if (memcmp(&http_data[offset], "User-Agent:", 11) == 0) {
			// skip this field
			offset += 11;
		}
		else if (memcmp(&http_data[offset], "Accept:", 7) == 0) {
			// skip this field
			offset += 7;
		}
		else if (memcmp(&http_data[offset], "Accept-Encoding:", 16) == 0) {
			// skip this field
			offset += 16;
		}
		else if (memcmp(&http_data[offset], "Connection:", 11) == 0) {
			// skip this field
			offset += 11;
		}
		else if (memcmp(&http_data[offset], "\r\n", 2) == 0) {
			// The header ends with a blank line
			offset += 2;
			break;
		}
		else {
			offset++;
		}
	}

}


//初始化wincap: 成功返回0 不成功返回1
bool CNetCaptureDlg::initCap()
{
	n_dev = 0;
	if (pcap_findalldevs(&alldev, errbuf) == -1) //dev = 网卡链表头，遍历网卡链表
		return 1; //初始化出错

	for (dev = alldev; dev; dev = dev->next)
		n_dev++;
	return 0;
}

//开始抓包 异常返回-1 
int CNetCaptureDlg::start()
{
	int dev_index;
	int i = 0;
	u_int mask;
	struct bpf_program fcode;
	char* filter_ch;

	/* dev := 选择的网卡, 创建【抓包句柄】handle */
	initCap();
	//.GetCurSel:返回光标选中的[下标]，如果没有选中返回CB_ERR
	dev_index = this->m_selector.GetCurSel(); //鼠标点击的网卡
	if (dev_index == 0 || dev_index == CB_ERR)//没选或没得选
	{
		MessageBox(_T("请选择一个网卡"));
		return -1;
	}
	dev = alldev;
	for (i = 1; i < dev_index; i++)
		dev = dev->next;
	/*  pacp_open_live 针对指定的网卡创建一个【捕获句柄】，返回句柄指针
	pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)
	{
		pcap_t *p;
		// 基于指定的设备接口创建一个pcap句柄
		p = pcap_create(device, errbuf);
		// 设置最大捕获包的长度
		status = pcap_set_snaplen(p, snaplen);
		// 设置数据包的捕获模式
		status = pcap_set_promisc(p, promisc);
		// 设置执行捕获操作的持续时间
		status = pcap_set_timeout(p, to_ms);
		// 使指定pcap句柄进入活动状态，这里实际包含了创建捕获套接字的动作
		status = pcap_activate(p);
		return p;
	}*/
	//当前网卡，最大包长65536，【混杂模式】，持续1000ms, errbuf
	// 
	//通过调用pcap_open_live()函数打开一个网络接口并创建一个pcap对象，以进行后续的抓包操作
	if ((handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		MessageBox(_T("无法使用网卡:" + CString(dev->description)));
		pcap_freealldevs(alldev);
		return -1;
	}
	//返回链路层类型，只分析常规的以太网
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		MessageBox(_T("当前选择网卡不是以太网卡"));
		pcap_freealldevs(alldev);
		return -1;
	}

	/* set过滤器 */
	/* mask:= 获取子网掩码
	pacp_addr有五个属性，ip地址、子网掩码、广播地址、目标地址
		struct sockaddr_in{
			sa_family_t		sin_family;   //地址族
			uint16_t		sin_port;     //端口号
			struct  in_addr sin_addr;     //32位IP地址
			char			sin_zero;      //预留未使用
		};
	*/
	if (dev->addresses != NULL)
		mask = ((struct sockaddr_in*)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		mask = 0xffffffff;//default = /32

	int len = this->filter.GetLength() + 1;
	if (len != 0)
	{
		filter_ch = (char*)malloc(len);
		for (i = 0; i < len; i++)
			filter_ch[i] = this->filter.GetAt(i);
		if (pcap_compile(handle, &fcode, filter_ch, 1, mask) < 0)
		{
			MessageBox(_T("编译器规则错误，请重新输入后再次确认"));
			pcap_freealldevs(alldev);
			return -1;
		}
		if (pcap_setfilter(handle, &fcode) < 0)
		{
			MessageBox(_T("编译器编译通过但设置出错"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}

	/* myfile:= 包存储位置 */
	CFileFind file;
	char thistime[30];
	struct tm* ltime = NULL;
	memset(filepath, 0, 512);
	memset(filename, 0, 512);
	if (!file.FindFile(_T("SavedDir")))
	{
		CreateDirectory(_T("SavedDir"), NULL);
	}
	// 代码获取当前的时间，将其格式化为"%Y%m%d %H%M%S"的形式，
	// 并将其作为文件名的一部分。然后将文件名与文件夹路径拼接起来
	time_t nowtime;
	time(&nowtime);
	ltime = localtime(&nowtime);
	strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", ltime);
	strcpy(filepath, "SavedDir\\");
	strcat(filename, thistime);
	strcat(filename, ".pkt");

	// 代码调用pcap_dump_open函数来创建一个pcap_dumper_t对象，
	// 用于将捕获到的数据包存储到文件中。
	strcat(filepath, filename);
	myfile = pcap_dump_open(handle, filepath);
	if (myfile == NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1;
	}

	pcap_freealldevs(alldev);

	/* m_threadhandle:= 抓包线程句柄 创建抓包线程 */
	//代码通过CreateThread函数创建一个抓包线程，
	//传入了一个指向该类实例的指针作为参数，将线程句柄保存在m_threadhandle变量中
	LPDWORD threadcap = NULL;
	if ((m_threadhandle = CreateThread(NULL, 0, capture, this, 0, threadcap)) == NULL)
	{
		MessageBox(_T("创建抓包线程失败"));
		return -1;
	}
	return 1;
}

//数据包另存为
int CNetCaptureDlg::savefile()
{
	CFileFind findfile;
	if (findfile.FindFile(CString(filepath)) == NULL)
	{
		MessageBox(_T("没有找到文件保存路径"));
		return -1;
	}
	//false 表示另存为
	CFileDialog FileDlg(FALSE, _T("pkt"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	if (FileDlg.DoModal() == IDOK)
		CopyFile(CString(filepath), FileDlg.GetPathName(), TRUE);
	return 0;
}

//CString转char* 用于readfile转换文件地址为char*才能openoffline
//用于将MFC中的CString类型转换为char类型，以便在pcap_open_offline
//函数中打开离线保存的数据包文件。因为pcap_open_offline函数只接受
//char类型的参数作为文件名，所以需要将CString类型转换为char*类型才能正确调用该函数。
void CString2char(CString s, int len, char* c)
{
	int i;
	memset(c, 0, len);
	for (i = 0; i < len; i++)
		c[i] = (char)s.GetAt(i);
}

//读取数据包文件
int CNetCaptureDlg::readfile(CString filepath)
{
	int indexItem;
	struct tm* ltime = NULL;
	time_t time_T;
	CString timestring, buf;
	/*struct pcap_pkthdr {
	struct timeval ts;		/time stamp
	bpf_u_int32 caplen;		/length of portion present
	bpf_u_int32 len;		/length this packet (off wire)
	};  */
	struct pcap_pkthdr* head;	  //获取网络包头部
	const u_char* pktdata = NULL; //获取当前网络包数据部分
	u_char* pktdata_bk;			  //网络包数据部分备份
	pcap_t* fp;					//文件指针

	/* 转换文件路径格式为char* */
	int len = filepath.GetLength() + 1;
	char* charpath = (char*)malloc(len);
	if (charpath == NULL)
		return -1;
	CString2char(filepath, len, charpath);

	/* 打开文件 */
	if ((fp = pcap_open_offline(charpath, errbuf)) == NULL)
	{
		MessageBox(_T("打开文件失败") + CString(errbuf));
		return -1;
	}
	free(charpath);
	/* 遍历文件中的每个包 数据存到pktdata */
	while ((pcap_next_ex(fp, &head, &pktdata)) >= 0)
	{
		/* 申请空当前包规范结构体 */
		struct pkt_T* package_T = (struct pkt_T*)malloc(sizeof(struct pkt_T));
		if (package_T)
			memset(package_T, 0, sizeof(struct pkt_T));
		//异常：内存不够
		if (package_T == NULL)
		{
			MessageBox(_T("分配内存失败：分析包申请内存失败"));
			return -1;
		}
		/* 从外向内分析各层数据 如果失败就continue分析下个包 */
		/* 将 pktdata 不断向 package_T 中各个结构体赋值，使得抓包数据规范化 */
		if (analyze_frame(pktdata, package_T, &(this->pkcount_T)))
			continue;
		//更新统计信息
		this->n_pkt++;
		//备份包数据加入链表
		pktdata_bk = (u_char*)malloc(head->len);
		if (pktdata_bk)
			memcpy(pktdata_bk, pktdata, head->len);
		//加入链表
		this->m_localDataList.AddTail(package_T);
		this->m_netDataList.AddTail(pktdata_bk);
		//时间 长度
		package_T->len = head->len;
		time_T = head->ts.tv_sec;
		ltime = localtime(&time_T);
		package_T->time[0] = ltime->tm_year - 100; // 这里年从1900计数
		package_T->time[1] = ltime->tm_mon + 1;
		package_T->time[2] = ltime->tm_mday;
		package_T->time[3] = ltime->tm_hour;
		package_T->time[4] = ltime->tm_min;
		package_T->time[5] = ltime->tm_sec;
		/* window显示 */
		//序号
		buf.Format(_T("%d"), this->n_pkt); //插入item需要字符串
		indexItem = this->m_list1.InsertItem(this->n_pkt, buf);
		//时间
		timestring.Format(_T("%d.%d.%d-%d:%d:%d"), package_T->time[0], package_T->time[1],
			package_T->time[2], package_T->time[3], package_T->time[4], package_T->time[5]);
		this->m_list1.SetItemText(indexItem, 1, timestring);
		//长度
		buf.Empty();
		buf.Format(_T("%d"), package_T->len);
		this->m_list1.SetItemText(indexItem, 2, buf);
		//源Mac
		buf.Empty();
		buf.Format(_T("%02x-%02x-%02x-%02x-%02x-%02x"), package_T->ethh->src[0], package_T->ethh->src[1]
			, package_T->ethh->src[2], package_T->ethh->src[3], package_T->ethh->src[4]
			, package_T->ethh->src[5]);
		this->m_list1.SetItemText(indexItem, 3, buf);
		//目的Mac
		buf.Empty();
		buf.Format(_T("%02x-%02x-%02x-%02x-%02x-%02x"), package_T->ethh->dest[0], package_T->ethh->dest[1]
			, package_T->ethh->dest[2], package_T->ethh->dest[3], package_T->ethh->dest[4]
			, package_T->ethh->dest[5]);
		this->m_list1.SetItemText(indexItem, 4, buf);
		//协议类型
		this->m_list1.SetItemText(indexItem, 5, CString(package_T->pktType));
		//源IP
		buf.Empty();
		if (package_T->ethh->type == MACTYPE_IP) //ip包
		{
			struct in_addr ip; //ip地址的结构体
			ip.S_un.S_addr = package_T->iph->saddr;
			buf = CString(inet_ntoa(ip)); // 转十进制字符串
		}
		else if (package_T->ethh->type == MACTYPE_ARP) //arp包
		{
			buf.Format(_T("%d.%d.%d.%d"), package_T->arph->ar_srcip[0], package_T->arph->ar_srcip[1],
				package_T->arph->ar_srcip[2], package_T->arph->ar_srcip[3]);
		}
		else if (package_T->ethh->type == MACTYPE_IP6) //ipv6包
		{
			buf.Format(_T("%x:%x:%x:%x:%x:%x:%x:%x"), package_T->iph6->saddr[0], package_T->iph6->saddr[1],
				package_T->iph6->saddr[2], package_T->iph6->saddr[3], package_T->iph6->saddr[4],
				package_T->iph6->saddr[5], package_T->iph6->saddr[6], package_T->iph6->saddr[7]);
		}
		this->m_list1.SetItemText(indexItem, 6, buf);
		//目的ip
		buf.Empty();
		if (package_T->ethh->type == MACTYPE_IP) //ip包
		{
			struct in_addr ip; //ip地址的结构体
			ip.S_un.S_addr = package_T->iph->daddr;
			buf = CString(inet_ntoa(ip)); // 转十进制字符串
		}
		else if (package_T->ethh->type == MACTYPE_ARP) //arp包
		{
			buf.Format(_T("%d.%d.%d.%d"), package_T->arph->ar_destip[0], package_T->arph->ar_destip[1],
				package_T->arph->ar_destip[2], package_T->arph->ar_destip[3]);
		}
		else if (package_T->ethh->type == MACTYPE_IP6) //ipv6包
		{
			buf.Format(_T("%x:%x:%x:%x:%x:%x:%x:%x"), package_T->iph6->daddr[0], package_T->iph6->daddr[1],
				package_T->iph6->daddr[2], package_T->iph6->daddr[3], package_T->iph6->daddr[4],
				package_T->iph6->daddr[5], package_T->iph6->daddr[6], package_T->iph6->daddr[7]);
		}
		this->m_list1.SetItemText(indexItem, 7, buf);
	}
	pcap_close(fp);
	return 1;
}

//抓包线程 被strat调用
DWORD WINAPI capture(LPVOID lpParameter)
{
//pktdata_bk: 存储上一次抓取的数据包的内容，用于比较两次抓取的数据包是否相同
//pktdata: 存储当前抓取的数据包的内容，用于检测数据包的特征
//package_T: 存储数据包的相关信息，如数据包的来源和目的IP地址、端口号、协议类型等

	int indexItem, res;
	CString timestring, buf;
	time_t time_T;
	struct tm* ltime;
	struct pcap_pkthdr* head;
	const u_char* pkt_data = NULL;
	u_char* pktdata_bk; //备份包数据到链表

	CNetCaptureDlg* bpthis = (CNetCaptureDlg*)lpParameter;
	if (bpthis->m_threadhandle == NULL)
	{
		MessageBox(NULL, _T("线程句柄错误"), _T("提示"), MB_OK);
		return -1;
	}
	/* 遍历文件中的每个包 数据存到pktdata */
	while ((res = pcap_next_ex(bpthis->handle, &head, &pkt_data)) >= 0)
	{
		//抓包超时
		if (res == 0)
			continue;
		/* 申请空当前包规范结构体 */
		struct pkt_T* package_T = (struct pkt_T*)malloc(sizeof(struct pkt_T));
		if (package_T)
			memset(package_T, 0, sizeof(struct pkt_T));
		//异常：内存不够
		if (package_T == NULL)
		{
			MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
			return -1;
		}
		/* 从外向内分析各层数据 如果失败就continue分析下个包 */
		/* 将 pktdata 不断向 package_T 中各个结构体赋值，使得抓包数据规范化 */
		if (analyze_frame(pkt_data, package_T, &(bpthis->pkcount_T)))
		{
			MessageBox(NULL, _T("当前解析包异常！"), _T("Error"), MB_OK);
			continue;
		}
		//将数据包保存到打开的文件中
		if (bpthis->myfile != NULL)
		{
			pcap_dump((unsigned char*)bpthis->myfile, head, pkt_data);
		}
		//更新统计信息
		bpthis->n_pkt++;
		//备份包数据加入链表
		pktdata_bk = (u_char*)malloc(head->len);
		if (pktdata_bk)
			memcpy(pktdata_bk, pkt_data, head->len);
		//加入链表
		bpthis->m_localDataList.AddTail(package_T);
		bpthis->m_netDataList.AddTail(pktdata_bk);
		//时间 长度
		package_T->len = head->len;
		time_T = head->ts.tv_sec;
		ltime = localtime(&time_T);
		package_T->time[0] = ltime->tm_year - 100; // 这里年从1900计数
		package_T->time[1] = ltime->tm_mon + 1;
		package_T->time[2] = ltime->tm_mday;
		package_T->time[3] = ltime->tm_hour;
		package_T->time[4] = ltime->tm_min;
		package_T->time[5] = ltime->tm_sec;
		/* window显示 */
		//将捕获到的数据包的相关信息插入到一个列表控件中，用于在GUI界面上显示出来
		//这段代码先生成需要插入的数据，然后通过列表控件的相关函数将其插入到对应的位置上。
		//序号
		buf.Format(_T("%d"), bpthis->n_pkt); //插入item需要字符串
		indexItem = bpthis->m_list1.InsertItem(bpthis->n_pkt, buf);
		//时间
		timestring.Format(_T("%d.%d.%d-%d:%d:%d"), package_T->time[0], package_T->time[1],
			package_T->time[2], package_T->time[3], package_T->time[4], package_T->time[5]);
		bpthis->m_list1.SetItemText(indexItem, 1, timestring);
		//长度
		buf.Empty();
		buf.Format(_T("%d"), package_T->len);
		bpthis->m_list1.SetItemText(indexItem, 2, buf);
		//源Mac
		buf.Empty();
		buf.Format(_T("%02x-%02x-%02x-%02x-%02x-%02x"), package_T->ethh->src[0], package_T->ethh->src[1]
			, package_T->ethh->src[2], package_T->ethh->src[3], package_T->ethh->src[4]
			, package_T->ethh->src[5]);
		bpthis->m_list1.SetItemText(indexItem, 3, buf);
		//目的Mac
		buf.Empty();
		buf.Format(_T("%02x-%02x-%02x-%02x-%02x-%02x"), package_T->ethh->dest[0], package_T->ethh->dest[1]
			, package_T->ethh->dest[2], package_T->ethh->dest[3], package_T->ethh->dest[4]
			, package_T->ethh->dest[5]);
		bpthis->m_list1.SetItemText(indexItem, 4, buf);
		//协议类型
		bpthis->m_list1.SetItemText(indexItem, 5, CString(package_T->pktType));


		// 根据不同类型的数据包采取不同格式的提取和展示
		// 通过判断数据包的类型（IP、ARP、IPv6）来获取其源IP和目的IP地址
		//源IP
		buf.Empty();
		if (package_T->ethh->type == MACTYPE_IP) //ip包
		{
			struct in_addr ip; //ip地址的结构体
			ip.S_un.S_addr = package_T->iph->saddr;
			buf = CString(inet_ntoa(ip)); // 转十进制字符串
		}
		else if (package_T->ethh->type == MACTYPE_ARP) //arp包
		{
			buf.Format(_T("%d.%d.%d.%d"), package_T->arph->ar_srcip[0], package_T->arph->ar_srcip[1],
				package_T->arph->ar_srcip[2], package_T->arph->ar_srcip[3]);
		}
		else if (package_T->ethh->type == MACTYPE_IP6) //ipv6包
		{
			buf.Format(_T("%x:%x:%x:%x:%x:%x:%x:%x"), package_T->iph6->saddr[0], package_T->iph6->saddr[1],
				package_T->iph6->saddr[2], package_T->iph6->saddr[3], package_T->iph6->saddr[4],
				package_T->iph6->saddr[5], package_T->iph6->saddr[6], package_T->iph6->saddr[7]);
		}
		bpthis->m_list1.SetItemText(indexItem, 6, buf);
		//目的ip
		buf.Empty();
		if (package_T->ethh->type == MACTYPE_IP) //ip包
		{
			struct in_addr ip; //ip地址的结构体
			ip.S_un.S_addr = package_T->iph->daddr;
			buf = CString(inet_ntoa(ip)); // 转十进制字符串
		}
		else if (package_T->ethh->type == MACTYPE_ARP) //arp包
		{
			buf.Format(_T("%d.%d.%d.%d"), package_T->arph->ar_destip[0], package_T->arph->ar_destip[1],
				package_T->arph->ar_destip[2], package_T->arph->ar_destip[3]);
		}
		else if (package_T->ethh->type == MACTYPE_IP6) //ipv6包
		{
			buf.Format(_T("%x:%x:%x:%x:%x:%x:%x:%x"), package_T->iph6->daddr[0], package_T->iph6->daddr[1],
				package_T->iph6->daddr[2], package_T->iph6->daddr[3], package_T->iph6->daddr[4],
				package_T->iph6->daddr[5], package_T->iph6->daddr[6], package_T->iph6->daddr[7]);
		}
		bpthis->m_list1.SetItemText(indexItem, 7, buf);
	}
	return 1;
}

//列表染色函数
void CNetCaptureDlg::OnNMCustomdrawList2(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLVCUSTOMDRAW pNMCD = reinterpret_cast<LPNMLVCUSTOMDRAW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	if (pNMCD->nmcd.dwDrawStage == CDDS_PREPAINT)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (pNMCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		COLORREF color = NULL;
		char tmp[8];
		memset(tmp, 0, 8);
		POSITION index = this->m_localDataList.FindIndex(pNMCD->nmcd.dwItemSpec);
		struct pkt_T* pkt = (struct pkt_T*)this->m_localDataList.GetAt(index);
		strcpy(tmp, pkt->pktType);
		//染色
		{
			if (strcmp(tmp, "IPV6") == 0)
				color = RGB(254, 224, 254);
			else if (strcmp(tmp, "UDP") == 0)
				color = RGB(194, 195, 252);
			else if (strcmp(tmp, "TCP") == 0)
				color = RGB(5, 234, 13);
			else if (strcmp(tmp, "ARP") == 0)
				color = RGB(245, 50, 10);
			else if (strcmp(tmp, "ICMP") == 0)
				color = RGB(50, 165, 235);
			else if (strcmp(tmp, "HTTP") == 0)
				color = RGB(235, 230, 170);
			else if (strcmp(tmp, "ICMPv6") == 0)
				color = RGB(190, 255, 70);
			else if (strcmp(tmp, "HTTPS") == 0)
				color = RGB(254, 232, 130);
			else if (strcmp(tmp, "DNS") == 0)
				color = RGB(78, 29, 76);
			else if (strcmp(tmp, "FTP") == 0)
				color = RGB(62, 188, 202);
		}
		pNMCD->clrTextBk = color;
		*pResult = CDRF_DODEFAULT;
	}
}

// 对于一个以太网数据包，它可能包含了以太网协议头、IP协议头和TCP协议头等多个协议。
// 当 updateTree 函数接收到该数据包时，它首先遍历所有根节点，查找名为“Ethernet”的子节点。
// 如果找到该子节点，则在该子节点下创建一个名为“IP”的新子节点；如果找不到该子节点，
// 则在根节点下创建一个名为“Ethernet”的子节点，并在该子节点下创建一个名为“IP”的新子节点。
// 然后，在“IP”子节点下再创建一个名为“TCP”的新子节点，用于表示TCP协议头的信息。
// 这样，就实现了对数据包的分层表示，方便用户查看和分析数据包的结构和内容。
// 
//更新包解析树
int CNetCaptureDlg::updateTree(int index)
{
	/* 清空树 */
	this->m_tree1.DeleteAllItems();
	/* 初始化 */
	CString buf;
	POSITION localpos = this->m_localDataList.FindIndex(index);
	struct pkt_T* package_T = (struct pkt_T*)(this->m_localDataList.GetAt(localpos));
	/* 树根 */
	buf.Format(_T("第%d个包："), index + 1);
	HTREEITEM root = this->m_tree1.GetRootItem();
	HTREEITEM data = this->m_tree1.InsertItem(buf, root);
	/* dl层 */
	HTREEITEM frame = this->m_tree1.InsertItem(_T("链路层数据："), data);
	//src mac
	buf.Empty();
	buf.Format(_T("源MAC: "));
	buf.AppendFormat(_T("%02x-%02x-%02x-%02x-%02x-%02x"), package_T->ethh->src[0], package_T->ethh->src[1]
		, package_T->ethh->src[2], package_T->ethh->src[3], package_T->ethh->src[4]
		, package_T->ethh->src[5]);
	this->m_tree1.InsertItem(buf, frame);
	//dst mac
	buf.Empty();
	buf.Format(_T("目的MAC: "));
	buf.AppendFormat(_T("%02x-%02x-%02x-%02x-%02x-%02x"), package_T->ethh->dest[0], package_T->ethh->dest[1]
		, package_T->ethh->dest[2], package_T->ethh->dest[3], package_T->ethh->dest[4]
		, package_T->ethh->dest[5]);
	this->m_tree1.InsertItem(buf, frame);
	//type
	buf.Empty();
	buf.Format(_T("类型；0x%04x"), package_T->ethh->type);
	this->m_tree1.InsertItem(buf, frame);
	/* ip层 */
	switch (package_T->ethh->type)
	{
		/* IPv4 */
	case MACTYPE_IP: {
		HTREEITEM ip = this->m_tree1.InsertItem(_T("IPv4协议头："), data);

		buf.Format(_T("版本号；%d"), package_T->iph->version);
		this->m_tree1.InsertItem(buf, ip);
		buf.Format(_T("IPv4头长；%d*4字节"), package_T->iph->ihl);
		this->m_tree1.InsertItem(buf, ip);
		buf.Format(_T("服务类型；%d"), package_T->iph->tos);
		this->m_tree1.InsertItem(buf, ip);
		buf.Format(_T("IPv4包总长度；%d字节"), package_T->iph->tlen);
		this->m_tree1.InsertItem(buf, ip);
		buf.Format(_T("ID标识；0x%02x"), package_T->iph->id);
		this->m_tree1.InsertItem(buf, ip);
		int mask_frag = 0b11100000;
		buf.Format(_T("标志位；%d"), ((package_T->iph->frag_off) & mask_frag) >> 5);
		this->m_tree1.InsertItem(buf, ip);
		buf.Format(_T("段偏移；%d"),
			((((package_T->iph->frag_off) & 0b11111) << 8) + (((package_T->iph->frag_off) >> 8) & 0xff)) << 3);
		this->m_tree1.InsertItem(buf, ip);
		buf.Format(_T("TTL；%d"), package_T->iph->ttl);
		this->m_tree1.InsertItem(buf, ip);
		buf.Format(_T("上层协议号；%d"), package_T->iph->proto);
		this->m_tree1.InsertItem(buf, ip);
		buf.Format(_T("头部校验和；0x%04x"), package_T->iph->check);
		this->m_tree1.InsertItem(buf, ip);

		//对于头部校验和字段等其他，需要将其以十六进制的形式表示
		//而对于IP地址字段，需要将其转换为点分十进制的形式表示


		struct in_addr ip_addr;
		ip_addr.S_un.S_addr = package_T->iph->saddr;
		buf.Format(_T("源IP："));
		buf.AppendFormat(CString(inet_ntoa(ip_addr)));
		this->m_tree1.InsertItem(buf, ip);

		ip_addr.S_un.S_addr = package_T->iph->daddr;
		buf.Format(_T("目的IP："));
		buf.AppendFormat(CString(inet_ntoa(ip_addr)));
		this->m_tree1.InsertItem(buf, ip);

		/* 传输层 */
		const u_char* type = &package_T->iph->proto; //上层协议类型
		//不同的上层协议可能包含不同的协议头信息和数据，
		//需要对这些信息进行不同的解析和显示
		switch (*type)
		{
			/* ICMP */
		case 1: {
			//使用m_treeCtrl.InsertItem函数在树形结构控件中创建一个名称为“ICMP协议头”的子节点
			HTREEITEM icmp = this->m_tree1.InsertItem(_T("ICMP协议头："), data);
			buf.Format(_T("类型：%d"), package_T->icmph->type);
			this->m_tree1.InsertItem(buf, icmp);
			buf.Format(_T("代码：%d"), package_T->icmph->code);
			this->m_tree1.InsertItem(buf, icmp);
			buf.Format(_T("序号：%d"), package_T->icmph->seq);
			this->m_tree1.InsertItem(buf, icmp);
			buf.Format(_T("校验和：%d"), package_T->icmph->chksum);
			this->m_tree1.InsertItem(buf, icmp);
			break; }
			  /* TCP */
		case 6: {
			HTREEITEM tcp = this->m_tree1.InsertItem(_T("TCP协议头："), data);
			buf.Format(_T("源端口：%d"), package_T->tcph->sport);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("目的端口：%d"), package_T->tcph->dport);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("序列号：0x%04x"), package_T->tcph->seq);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("确认号：0x%04x"), package_T->tcph->ack_seq);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("头部长度：%d*4字节"), package_T->tcph->doff);
			this->m_tree1.InsertItem(buf, tcp);

			HTREEITEM flag = this->m_tree1.InsertItem(_T(" 标志位："), tcp);
			buf.Format(_T("cwr窗口拥挤减少 = %d"), package_T->tcph->cwr);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("ece显式拥塞提醒回应 = %d"), package_T->tcph->ece);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("urg紧急 = %d"), package_T->tcph->urg);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("ack应答 = %d"), package_T->tcph->ack);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("push立即推送 = %d"), package_T->tcph->psh);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("rst重链接 = %d"), package_T->tcph->rst);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("syn同步 = %d"), package_T->tcph->syn);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("fin终止 = %d"), package_T->tcph->fin);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("窗口大小：%d"), package_T->tcph->window);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("报文校验和：0x%04x"), package_T->tcph->check);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("紧急指针：%d"), package_T->tcph->urg_ptr);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("选项：%d"), package_T->tcph->opt);
			this->m_tree1.InsertItem(buf, tcp);

			//检查是否是HTTP数据包
			if (package_T->tcph->dport == htons(80) || package_T->tcph->sport == htons(80))
			{
				//在树状图控件中插入一个名为“HTTP协议头”的树节点，并将数据包信息作为该节点的数据项
				HTREEITEM http = this->m_tree1.InsertItem(_T("HTTP协议头："), data);
				HTTP_HEADER* http_header = new HTTP_HEADER;
				CString header;

				// 解析 HTTP 报文头信息
				parseHttpHeader(package_T->data, package_T->len, *http_header);

				// 将 HTTP 报文头信息添加到树状图控件中
				CString buf;
				buf.Format(_T("版本：%s"), http_header->version);
				this->m_tree1.InsertItem(buf, http);
				buf.Format(_T("方法：%s"), http_header->method);
				this->m_tree1.InsertItem(buf, http);
				buf.Format(_T("URL：%s"), http_header->url);
				this->m_tree1.InsertItem(buf, http);
				buf.Format(_T("主机：%s"), http_header->host);
				this->m_tree1.InsertItem(buf, http);
				/*buf.Format(_T("连接：%s"), http_header->connection);
				this->m_tree1.InsertItem(buf, http);
				buf.Format(_T("内容长度：%d"), http_header->content_length);
				this->m_tree1.InsertItem(buf, http);
				buf.Format(_T("用户代理：%s"), http_header->user_agent);
				this->m_tree1.InsertItem(buf, http);*/

				delete http_header;
			}
			break; }

			  /* UDP */
		case 17: {
			HTREEITEM udp = this->m_tree1.InsertItem(_T("UDP协议头："), data);
			buf.Format(_T("源端口：%d"), package_T->udph->sport);
			this->m_tree1.InsertItem(buf, udp);
			buf.Format(_T("目的端口：%d"), package_T->udph->dport);
			this->m_tree1.InsertItem(buf, udp);
			buf.Format(_T("报文长度：%d"), package_T->udph->len);
			this->m_tree1.InsertItem(buf, udp);
			buf.Format(_T("校验和：0x%04x"), package_T->udph->check);
			this->m_tree1.InsertItem(buf, udp);
			break; }
		default: {
			HTREEITEM other = this->m_tree1.InsertItem(_T("IP上层非常见协议："), data);
			buf.Format(_T("协议号：%d"), package_T->iph->proto);
			this->m_tree1.InsertItem(buf, other);
			break; }
		}
		break; }
				   /* ARP */
	case MACTYPE_ARP: {
		HTREEITEM arp = this->m_tree1.InsertItem(_T("ARP协议头："), data);

		buf.Format(_T("硬件接口类型：%d"), package_T->arph->ar_hrd);
		this->m_tree1.InsertItem(buf, arp);
		buf.Format(_T("依附协议类型：0x%04x"), package_T->arph->ar_pro);
		this->m_tree1.InsertItem(buf, arp);
		buf.Format(_T("硬件地址长度：%d*字节"), package_T->arph->ar_hln);
		this->m_tree1.InsertItem(buf, arp);
		buf.Format(_T("协议地址长度：%d*字节"), package_T->arph->ar_pln);
		this->m_tree1.InsertItem(buf, arp);
		if (package_T->arph->ar_op == 1)
		{
			buf.Format(_T("操作码：%d(ARP请求)"), package_T->arph->ar_op);
			this->m_tree1.InsertItem(buf, arp);
		}
		else if (package_T->arph->ar_op == 2)
		{
			buf.Format(_T("操作码：%d(ARP响应)"), package_T->arph->ar_op);
			this->m_tree1.InsertItem(buf, arp);
		}
		else
		{
			buf.Format(_T("操作码：%d"), package_T->arph->ar_op);
			this->m_tree1.InsertItem(buf, arp);
		}
		buf.Format(_T("发送方MAC: "));
		buf.AppendFormat(_T("%02x-%02x-%02x-%02x-%02x-%02x"), package_T->arph->ar_srcmac[0], package_T->arph->ar_srcmac[1]
			, package_T->arph->ar_srcmac[2], package_T->arph->ar_srcmac[3], package_T->arph->ar_srcmac[4]
			, package_T->arph->ar_srcmac[5]);
		this->m_tree1.InsertItem(buf, arp);
		buf.Format(_T("发送方IP: "));
		buf.AppendFormat(_T("%d.%d.%d.%d"), package_T->arph->ar_srcip[0], package_T->arph->ar_srcip[1],
			package_T->arph->ar_srcip[2], package_T->arph->ar_srcip[3]);
		this->m_tree1.InsertItem(buf, arp);
		buf.Format(_T("接收方MAC: "));
		buf.AppendFormat(_T("%02x-%02x-%02x-%02x-%02x-%02x"), package_T->arph->ar_destmac[0], package_T->arph->ar_destmac[1]
			, package_T->arph->ar_destmac[2], package_T->arph->ar_destmac[3], package_T->arph->ar_destmac[4]
			, package_T->arph->ar_destmac[5]);
		this->m_tree1.InsertItem(buf, arp);
		buf.Format(_T("接受方IP: "));
		buf.AppendFormat(_T("%d.%d.%d.%d"), package_T->arph->ar_destip[0], package_T->arph->ar_destip[1],
			package_T->arph->ar_destip[2], package_T->arph->ar_destip[3]);
		this->m_tree1.InsertItem(buf, arp);
		break; }
					/* IPv6 */
	case MACTYPE_IP6: {
		HTREEITEM ip6 = this->m_tree1.InsertItem(_T("IPv6协议头："), data);

		buf.Format(_T("版本号：%d"), package_T->iph6->version);
		this->m_tree1.InsertItem(buf, ip6);
		buf.Format(_T("流服务类型：%d"), package_T->iph6->flowtype);
		this->m_tree1.InsertItem(buf, ip6);
		buf.Format(_T("流标签：%d"), package_T->iph6->flowid);
		this->m_tree1.InsertItem(buf, ip6);
		buf.Format(_T("净荷长度：%d*字节"), package_T->iph6->plen);
		this->m_tree1.InsertItem(buf, ip6);
		buf.Format(_T("扩展头部/上层协议头：0x%02x"), package_T->iph6->nh);
		this->m_tree1.InsertItem(buf, ip6);
		buf.Format(_T("TTL：%d"), package_T->iph6->hlim);
		this->m_tree1.InsertItem(buf, ip6);
		buf.Format(_T("源IPv6："));
		buf.AppendFormat(_T("%x:%x:%x:%x:%x:%x:%x:%x"), package_T->iph6->saddr[0], package_T->iph6->saddr[1],
			package_T->iph6->saddr[2], package_T->iph6->saddr[3], package_T->iph6->saddr[4],
			package_T->iph6->saddr[5], package_T->iph6->saddr[6], package_T->iph6->saddr[7]);
		this->m_tree1.InsertItem(buf, ip6);
		buf.Format(_T("目的IPv6："));
		buf.AppendFormat(_T("%x:%x:%x:%x:%x:%x:%x:%x"), package_T->iph6->daddr[0], package_T->iph6->daddr[1],
			package_T->iph6->daddr[2], package_T->iph6->daddr[3], package_T->iph6->daddr[4],
			package_T->iph6->daddr[5], package_T->iph6->daddr[6], package_T->iph6->daddr[7]);
		this->m_tree1.InsertItem(buf, ip6);
		/* 传输层 */
		switch (package_T->iph6->nh)
		{
			/* TCP */
		case 0x06: {
			HTREEITEM tcp = this->m_tree1.InsertItem(_T("TCP协议头："), data);
			buf.Format(_T("源端口：%d"), package_T->tcph->sport);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("源端口：%d"), package_T->tcph->dport);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("序列号：%d"), package_T->tcph->seq);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("确认号：%d"), package_T->tcph->ack_seq);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("头部长度：%d*4字节"), package_T->tcph->doff);
			this->m_tree1.InsertItem(buf, tcp);

			HTREEITEM flag = this->m_tree1.InsertItem(_T(" 标志位："), tcp);
			buf.Format(_T("cwr窗口拥挤减少 = %d"), package_T->tcph->cwr);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("ece显式拥塞提醒回应 = %d"), package_T->tcph->ece);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("urg紧急 = %d"), package_T->tcph->urg);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("ack应答 = %d"), package_T->tcph->ack);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("push立即推送 = %d"), package_T->tcph->psh);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("rst重链接 = %d"), package_T->tcph->rst);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("syn同步 = %d"), package_T->tcph->syn);
			this->m_tree1.InsertItem(buf, flag);
			buf.Format(_T("fin终止 = %d"), package_T->tcph->fin);
			this->m_tree1.InsertItem(buf, flag);

			buf.Format(_T("报文校验和：0x%04x"), package_T->tcph->check);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("紧急指针：%d"), package_T->tcph->urg_ptr);
			this->m_tree1.InsertItem(buf, tcp);
			buf.Format(_T("选项：%d"), package_T->tcph->opt);
			this->m_tree1.InsertItem(buf, tcp);
			break; }
				 /* ICMPv6 */
		case 0x3a: {
			HTREEITEM icmp6 = this->m_tree1.InsertItem(_T("ICMPv6协议头："), data);
			buf.Format(_T("类型：%d"), package_T->icmph6->type);
			this->m_tree1.InsertItem(buf, icmp6);
			buf.Format(_T("代码：%d"), package_T->icmph6->code);
			this->m_tree1.InsertItem(buf, icmp6);
			buf.Format(_T("序号：%d"), package_T->icmph6->seq);
			this->m_tree1.InsertItem(buf, icmp6);
			buf.Format(_T("校验和：%d"), package_T->icmph6->chksum);
			this->m_tree1.InsertItem(buf, icmp6);
			buf.Format(_T("选项-类型：%d"), package_T->icmph6->op_type);
			this->m_tree1.InsertItem(buf, icmp6);
			buf.Format(_T("选项-长度%d"), package_T->icmph6->op_len);
			this->m_tree1.InsertItem(buf, icmp6);
			buf.Format(_T("选项-链路层地址："));
			int i;
			for (i = 0; i < 6; i++)
			{
				if (i <= 4)
					buf.AppendFormat(_T("%02x-"), package_T->icmph6->op_ethaddr[i]);
				else
					buf.AppendFormat(_T("%02x"), package_T->icmph6->op_ethaddr[i]);
			}
			this->m_tree1.InsertItem(buf, icmp6);
			break; }
				 /* UDP */
		case 0x11: {
			HTREEITEM udp = this->m_tree1.InsertItem(_T("UDP协议头："), data);
			buf.Format(_T("源端口：%d"), package_T->udph->sport);
			this->m_tree1.InsertItem(buf, udp);
			buf.Format(_T("目的端口：%d"), package_T->udph->dport);
			this->m_tree1.InsertItem(buf, udp);
			buf.Format(_T("报文长度：%d"), package_T->udph->len);
			this->m_tree1.InsertItem(buf, udp);
			buf.Format(_T("校验和：0x%04x"), package_T->udph->check);
			this->m_tree1.InsertItem(buf, udp);
			break; }
		default:
			break;
		}
		break; }
	default:
		this->m_tree1.InsertItem(_T("奇怪的帧，不能解析"), data);
		break;
	}
	return 1;
}





//更新包的详细信息
int CNetCaptureDlg::updateEdit(int index)
{
	CString buf;
	POSITION localpos = this->m_localDataList.FindIndex(index);
	POSITION netpos = this->m_netDataList.FindIndex(index);
	struct pkt_T* package_T = (struct pkt_T*)(this->m_localDataList.GetAt(localpos));
	u_char* package_data = (u_char*)(this->m_netDataList.GetAt(netpos));
	print_packet_hex(package_data, package_T->len, &buf);
	this->m_edit1.SetWindowText(buf); //自适应编码
	return 1;
}

//找第一个Ip包
//特征：flag == 1 && offset == 0 && id == tmp.id
struct pkt_T* FindFstIp(struct pkt_T* tmp, int& index, LPVOID lpParameter)
{
	struct pkt_T* fst = NULL;
	CNetCaptureDlg* bpthis = (CNetCaptureDlg*)lpParameter; //this指针

	int flag = (tmp->iph->frag_off & 0b11100000) >> 5;
	int offset = ((((tmp->iph->frag_off) & 0b11111) << 8) + (((tmp->iph->frag_off) >> 8) & 0xff)) << 3;

	if (flag == 1 && offset == 0)
		fst = tmp;
	else
	{
		POSITION localpos;
		POSITION netpos;

		while (!(flag == 1 && offset == 0))
		{
			//上找一个规范包
			index--;
			localpos = bpthis->m_localDataList.FindIndex(index);
			struct pkt_T* tmp1 = (struct pkt_T*)(bpthis->m_localDataList.GetAt(localpos));

			//如果是同id说明是同个分段的，更新tmp,flag,offset
			if (tmp1->iph != NULL && tmp1->iph->id == tmp->iph->id)
			{
				tmp = tmp1;
				flag = (tmp->iph->frag_off & 0b11100000) >> 5;
				offset = ((((tmp->iph->frag_off) & 0b11111) << 8) + (((tmp->iph->frag_off) >> 8) & 0xff)) << 3;
			}

			//如果到头了 而且也不是
			if (bpthis->m_localDataList.GetHead() == tmp1 && !(flag == 1 && offset == 0))
				return NULL;
		}

		fst = tmp;
	}
	return fst;
}
