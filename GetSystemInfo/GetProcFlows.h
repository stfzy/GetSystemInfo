#pragma once
#include "impl.h"
 

class CGetProcFlows
{
private:
	CGetProcFlows(void);
	static CGetProcFlows* m_sSingle;
public:
	static CGetProcFlows * GetInstance();
	BOOL GetProcFlows(PPROCFLOWINFOMAP * proinfo);
	BOOL LimitProcSpeed(ULONG pid, BOOL bForbitNet,LONG limitDown = -1,LONG limitUp = -1);
	BOOL RealGetFlowInfo(PPROCFLOWINFOMAP * proinfo,BYTE* pbHave);
	BOOL ClearProcFlow();
    PROCFLOWINFOMAP m_proFlowInfo;
};

