#include "stdafx.h"
#include "GetProcInfo.h"

 
#include "..\comm\comm.h"

CGetProcInfo * CGetProcInfo::m_singleGpi = 0;

CGetProcInfo::CGetProcInfo(void)
{
	InitializeCriticalSection(&m_cs);
	 
	//DebugPrMyMethod();

}


CGetProcInfo::~CGetProcInfo(void)
{
	DeleteCriticalSection(&m_cs);
	if(m_singleGpi)
		delete m_singleGpi;
}

void CGetProcInfo::GetProcInfo(PPROCINFOMAP * pProInfoList)
{ 
	EnterCriticalSection(&m_cs);
	BYTE bHave; 
	GetProcList2(pProInfoList, &bHave);
	map<DWORD, ProcInfo>::iterator it;
	it =  m_ProInfos.begin();

	while (it != m_ProInfos.end())
	{
		ProcInfo * p = &(*it).second;
		if (p->bBl == bHave)
		{ 
			if(p->hicoPro)
				DestroyIcon(p->hicoPro);
			CloseHandle(p->hpro);
			m_ProInfos.erase(it++);
			continue;
		}
		it++; 
		//Sleep(1);
	}
	LeaveCriticalSection(&m_cs);

 
}

CGetProcInfo * CGetProcInfo::GetInstance()
{
	if(m_singleGpi)
		return m_singleGpi;

	m_singleGpi = new CGetProcInfo;
	return m_singleGpi;

}
