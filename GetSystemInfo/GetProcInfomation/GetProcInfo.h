

#pragma once 
#include "..\GetProcList\GetProcList.h"
 
class CGetProcInfo : public CGetProcList
{
private:
	CRITICAL_SECTION m_cs;
	 
	CGetProcInfo(void);
	static CGetProcInfo * m_singleGpi;
public:
	~CGetProcInfo(void);
	static CGetProcInfo * GetInstance();
	void GetProcInfo(PPROCINFOMAP * pProInfoList); 
};

