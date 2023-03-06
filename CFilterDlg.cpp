// CFilterDlg.cpp: 实现文件
//

#include "pch.h"
#include "NetCapture.h"
#include "CFilterDlg.h"
#include "afxdialogex.h"
#include "framework.h"
#include "mstcpip.h"//加入tcpip头文件
#include "header.h"


// CFilterDlg 对话框

IMPLEMENT_DYNAMIC(CFilterDlg, CDialogEx)

CFilterDlg::CFilterDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

CFilterDlg::~CFilterDlg()
{
}

void CFilterDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    m_tcp.SetCheck(1);
    m_udp.SetCheck(1);
    m_arp.SetCheck(1);
    m_icmp.SetCheck(1);

    DDX_Control(pDX, IDC_CHECK2, m_tcp);
    DDX_Control(pDX, IDC_CHECK5, m_arp);
    DDX_Control(pDX, IDC_CHECK6, m_udp);
    DDX_Control(pDX, IDC_CHECK7, m_icmp);
}


BEGIN_MESSAGE_MAP(CFilterDlg, CDialogEx)
    ON_BN_CLICKED(IDC_CHECK2, &CFilterDlg::OnBnClickedCheck2)
    //ON_BN_CLICKED(IDC_CHECK6, &CFilterDlg::OnBnClickedCheck6)
    //ON_BN_CLICKED(IDC_CHECK5, &CFilterDlg::OnBnClickedCheck5)
    //ON_BN_CLICKED(IDC_CHECK7, &CFilterDlg::OnBnClickedCheck7)
    //ON_BN_CLICKED(IDOK, &CFilterDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CFilterDlg 消息处理程序

//TCP
//void CFilterDlg::OnBnClickedCheck2()
//{
    // TODO: 在此添加控件通知处理程序代码
//}

//ARP
//void CFilterDlg::OnBnClickedCheck6()
//{
    // TODO: 在此添加控件通知处理程序代码
//}

//UDP
//void CFilterDlg::OnBnClickedCheck5()
//{
    // TODO: 在此添加控件通知处理程序代码
//}

//ICMP
//void CFilterDlg::OnBnClickedCheck7()
//{
    // TODO: 在此添加控件通知处理程序代码
//}



//void CFilterDlg::OnBnClickedOk()
//{
//    CString filtername;
//    // TODO: 在此添加控件通知处理程序代码
//    if (1 == m_tcp.GetCheck())
//    {
//        filtername += _T("(tcp and ip) or ");
//    }
//    if (1 == m_udp.GetCheck())
//    {
//        filtername += _T("(udp and ip) or ");
//    }
//    if (1 == m_arp.GetCheck())
//    {
//        filtername += _T("arp or ");
//    }
//    if (1 == m_icmp.GetCheck())
//    {
//        filtername += _T("(icmp and ip) or ");
//    }
//
//    filtername = filtername.Left(filtername.GetLength() - 4);  //注意去掉最后多余的" or ",否则过滤规则不成立
//
//    CDialogEx::OnOK();
//}
