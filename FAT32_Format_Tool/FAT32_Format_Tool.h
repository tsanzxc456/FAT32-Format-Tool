
// FAT32_Format_Tool.h : PROJECT_NAME ���ε{�����D�n���Y��
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�� PCH �]�t���ɮ׫e���]�t 'stdafx.h'"
#endif

#include "resource.h"		// �D�n�Ÿ�


// CFAT32_Format_ToolApp:
// �аѾ\��@�����O�� FAT32_Format_Tool.cpp
//
;
class CFAT32_Format_ToolApp : public CWinApp
{
public:
	CFAT32_Format_ToolApp();

// �мg
public:
	virtual BOOL InitInstance();

// �{���X��@

	DECLARE_MESSAGE_MAP()
};

extern CFAT32_Format_ToolApp theApp;