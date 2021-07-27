
// FAT32_Format_ToolDlg.cpp : ��@��
//

#include "stdafx.h"
#include "format_function.h"
#include "FAT32_Format_Tool.h"
#include "FAT32_Format_ToolDlg.h"
#include "afxdialogex.h"
#include<iostream>
#include <string>
#include <vector>
#define ISBITSET(var, bit)   ((var)&(1<<(bit)))

//#include <stdlib.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
LPCWSTR drive_letter;

// �� App About �ϥ� CAboutDlg ��ܤ��

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// ��ܤ�����
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV �䴩

// �{���X��@
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CFAT32_Format_ToolDlg ��ܤ��




CFAT32_Format_ToolDlg::CFAT32_Format_ToolDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CFAT32_Format_ToolDlg::IDD, pParent)
	, m_rd_withoutMBR(0)
	, m_lastest_select(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CFAT32_Format_ToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_RD_withMBR, m_rd_withMBR);
	DDX_Control(pDX, IDC_CMB_disk, m_cmb_disk);
	DDX_Text(pDX, IDC_EDIT_selected, m_lastest_select);
	DDX_Control(pDX, IDC_CMB_SecOfCluster, m_cmb_secofcluster);
}

BEGIN_MESSAGE_MAP(CFAT32_Format_ToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_RD_withMBR, &CFAT32_Format_ToolDlg::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RD_withoutMBR, &CFAT32_Format_ToolDlg::OnBnClickedRdwithoutmbr)
	ON_EN_CHANGE(IDC_EDIT_Offset_of_FAT, &CFAT32_Format_ToolDlg::OnEnChangeEditOffsetofFat)
	ON_EN_CHANGE(IDC_EDIT_Offset_of_partition, &CFAT32_Format_ToolDlg::OnEnChangeEditOffsetofpartition)
	ON_BN_CLICKED(IDC_BUTTON_Format, &CFAT32_Format_ToolDlg::OnBnClickedButtonFormat)
	ON_CBN_SELCHANGE(IDC_CMB_disk, &CFAT32_Format_ToolDlg::OnCbnSelchangeCombo1)
	ON_CBN_SELCHANGE(IDC_CMB_SecOfCluster, &CFAT32_Format_ToolDlg::OnCbnSelchangeCombo2)
END_MESSAGE_MAP()


// CFAT32_Format_ToolDlg �T���B�z�`��

BOOL CFAT32_Format_ToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// �N [����...] �\���[�J�t�Υ\���C

	// IDM_ABOUTBOX �����b�t�ΩR�O�d�򤧤��C
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

	// �]�w����ܤ�����ϥܡC�����ε{�����D�������O��ܤ���ɡA
	// �ج[�|�۰ʱq�Ʀ��@�~
	SetIcon(m_hIcon, TRUE);			// �]�w�j�ϥ�
	SetIcon(m_hIcon, FALSE);		// �]�w�p�ϥ�

	// TODO: �b���[�J�B�~����l�]�w

	CheckRadioButton(IDC_RD_withMBR,IDC_RD_withoutMBR,IDC_RD_withMBR);

	TCHAR temp_ch[12];
	DWORD temp_dw = GetLogicalDrives();
	_itot(temp_dw,temp_ch,2);
	CString diskName;

	for(int i = 0; i < sizeof(temp_ch)/sizeof(TCHAR); i++){
		diskName.Format(_T("\\\\.\\%c:"),i+65);
		if(ISBITSET(temp_dw, i)){
			m_cmb_disk.AddString(diskName);
		}
	}


	CString Capacity;
	for(int i = 16; i <= 128 ; i*=2){
		Capacity.Format(_T("%d"),i);
		m_cmb_secofcluster.AddString(Capacity);
	}
	

	return TRUE;  // �Ǧ^ TRUE�A���D�z�ﱱ��]�w�J�I
}

void CFAT32_Format_ToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// �p�G�N�̤p�ƫ��s�[�J�z����ܤ���A�z�ݭn�U�C���{���X�A
// �H�Kø�s�ϥܡC���ϥΤ��/�˵��Ҧ��� MFC ���ε{���A
// �ج[�|�۰ʧ������@�~�C

void CFAT32_Format_ToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ø�s���˸m���e

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// �N�ϥܸm����Τ�ݯx��
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// �yø�ϥ�
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// ��ϥΪ̩즲�̤p�Ƶ����ɡA
// �t�ΩI�s�o�ӥ\����o�����ܡC
HCURSOR CFAT32_Format_ToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

bool MBR_flag = true;
ULONG cluster_size = 512;
ULONG Offset_of_FAT = 0;
ULONG Offset_of_partition = 0;


void CFAT32_Format_ToolDlg::OnBnClickedRadio1()
{
	// TODO: �b���[�J����i���B�z�`���{���X
	MBR_flag = true;
	m_lastest_select = _T("Format with MBR");
	UpdateData(FALSE);
}


void CFAT32_Format_ToolDlg::OnBnClickedRdwithoutmbr()
{
	// TODO: �b���[�J����i���B�z�`���{���X
	MBR_flag = false;
	m_lastest_select = _T("Format without MBR");
	UpdateData(FALSE);
}




void CFAT32_Format_ToolDlg::OnEnChangeEditOffsetofFat()
{
	// TODO:  �p�G�o�O RICHEDIT ����A����N���|
	// �ǰe���i���A���D�z�мg CDialogEx::OnInitDialog()
	// �禡�M�I�s CRichEditCtrl().SetEventMask()
	// ���㦳 ENM_CHANGE �X�� ORed �[�J�B�n�C

	// TODO:  �b���[�J����i���B�z�`���{���X
	TCHAR temp_ch[12];

	GetDlgItemText(IDC_EDIT_Offset_of_FAT, temp_ch, 12);
	Offset_of_FAT = _ttoi(temp_ch);
	CString  temp_str;  
	temp_str.Format(_T("%s"),temp_ch);
	//_itot(Offset_of_FAT,temp_ch2,10);
	//SetDlgItemText(IDC_EDIT_test, temp_ch2);

	m_lastest_select = _T("Offset of FAT = ") + temp_str + _T(" sectors");
	UpdateData(FALSE);

}


void CFAT32_Format_ToolDlg::OnEnChangeEditOffsetofpartition()
{
	// TODO:  �p�G�o�O RICHEDIT ����A����N���|
	// �ǰe���i���A���D�z�мg CDialogEx::OnInitDialog()
	// �禡�M�I�s CRichEditCtrl().SetEventMask()
	// ���㦳 ENM_CHANGE �X�� ORed �[�J�B�n�C

	// TODO:  �b���[�J����i���B�z�`���{���X
	TCHAR temp_ch[12];
	//TCHAR temp_ch2[12];

	GetDlgItemText(IDC_EDIT_Offset_of_partition, temp_ch, 12);
	Offset_of_partition = _ttoi(temp_ch);
	//_itot(Offset_of_partition,temp_ch2,10);
	//SetDlgItemText(IDC_EDIT_test, temp_ch2);
	CString  temp_str;  
	temp_str.Format(_T("%s"),temp_ch);

	m_lastest_select = _T("Offset of partitions = ") + temp_str + _T(" sectors");
	UpdateData(FALSE);
}



void CFAT32_Format_ToolDlg::OnBnClickedButtonFormat()
{
	

	TCHAR szVolumeName[MAX_PATH];
	//GetVolumeNameForVolumeMountPointW(drive_letter, szVolumeName, MAX_PATH);
	//SetDlgItemText(IDC_EDIT_test, szVolumeName);
	
	TCHAR temp_ch[12];
	int temp;
	LPCTSTR vol = (LPCTSTR)drive_letter;
	temp = format_volume(vol,MBR_flag, cluster_size, Offset_of_FAT, Offset_of_partition);

	_itot(temp,temp_ch,10);
	SetDlgItemText(IDC_EDIT_test, temp_ch);
	
	CString message;
	if(temp == 0)
	{
		message = CString(_T("Format Complete !"));
		AfxMessageBox(message);
	}
	else
	{
		message = CString(_T("Wrong !"));
		AfxMessageBox(message);
	}

	//////// test
	//TCHAR temp_ch[12];
	//int temp;
	//temp = format_volume();
	//_itot(temp,temp_ch,16);
	//SetDlgItemText(IDC_EDIT_test, temp_ch);
}


void CFAT32_Format_ToolDlg::OnCbnSelchangeCombo1()
{
	// TODO: �b���[�J����i���B�z�`���{���X
	int disk_selected = m_cmb_disk.GetCurSel();
	if (disk_selected != LB_ERR){
		m_cmb_disk.GetLBText(disk_selected, m_lastest_select);
		drive_letter = (LPWSTR)(LPCWSTR)m_lastest_select;
		UpdateData(FALSE);
	}

	TCHAR temp_ch[12];
	int Total_capacity = get_volume_capacity(drive_letter);
	Total_capacity /= 2;     // 2 Sector = 1 KB
	Total_capacity /= 1024;  // 1024 KB = 1 MB
	Total_capacity /= 1024;  // 1024 MB = 1 GB
	_itot(Total_capacity,temp_ch,10);
	SetDlgItemText(IDC_EDIT_CAPACITY, temp_ch);



}


void CFAT32_Format_ToolDlg::OnCbnSelchangeCombo2()
{
	// TODO: �b���[�J����i���B�z�`���{���X
	int sec_of_cluster_selected = m_cmb_secofcluster.GetCurSel();
	if (sec_of_cluster_selected != LB_ERR){
		m_cmb_secofcluster.GetLBText(sec_of_cluster_selected, m_lastest_select);
		cluster_size = _ttoi(m_lastest_select)*512;
		m_lastest_select = _T("Sectors Per Cluster = ") + m_lastest_select;
		UpdateData(FALSE);
	}
}
