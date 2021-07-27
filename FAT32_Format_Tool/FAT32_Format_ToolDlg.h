
// FAT32_Format_ToolDlg.h : ���Y��
//

#pragma once
#include "afxwin.h"


// CFAT32_Format_ToolDlg ��ܤ��
class CFAT32_Format_ToolDlg : public CDialogEx
{
// �غc
public:
	CFAT32_Format_ToolDlg(CWnd* pParent = NULL);	// �зǫغc�禡

// ��ܤ�����
	enum { IDD = IDD_FAT32_FORMAT_TOOL_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV �䴩


// �{���X��@
protected:
	HICON m_hIcon;

	// ���ͪ��T�������禡
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedRadio1();
	CButton m_rd_withMBR;
	int m_rd_withoutMBR;
	afx_msg void OnBnClickedRdwithoutmbr();
	afx_msg void OnBnClickedRd512();
	afx_msg void OnBnClickedRd1024();
	afx_msg void OnBnClickedRd2048();
	afx_msg void OnBnClickedRd4096();
	afx_msg void OnEnChangeEditOffsetofFat();
	afx_msg void OnEnChangeEditOffsetofpartition();
	afx_msg void OnBnClickedRd8192();
	afx_msg void OnBnClickedButtonFormat();
	afx_msg void OnCbnSelchangeCombo1();
	CComboBox m_cmb_disk;
	CEdit m_lastest_selection;
	CString m_lastest_select;
	afx_msg void OnCbnSelchangeCombo2();
	CComboBox m_cmb_secofcluster;
};
