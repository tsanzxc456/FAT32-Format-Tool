
// FAT32_Format_ToolDlg.h : 標頭檔
//

#pragma once
#include "afxwin.h"


// CFAT32_Format_ToolDlg 對話方塊
class CFAT32_Format_ToolDlg : public CDialogEx
{
// 建構
public:
	CFAT32_Format_ToolDlg(CWnd* pParent = NULL);	// 標準建構函式

// 對話方塊資料
	enum { IDD = IDD_FAT32_FORMAT_TOOL_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支援


// 程式碼實作
protected:
	HICON m_hIcon;

	// 產生的訊息對應函式
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
