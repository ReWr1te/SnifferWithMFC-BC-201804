
// WinPcapBeta2.0.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CWinPcapBeta20App: 
// �йش����ʵ�֣������ WinPcapBeta2.0.cpp
//

class CWinPcapBeta20App : public CWinApp
{
public:
	CWinPcapBeta20App();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CWinPcapBeta20App theApp;
