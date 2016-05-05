#include "StdAfx.h"

#define GETPROCINFO
#include "GetProcInfos.h"
#include "GetProcInfomation/GetProcInfo.h"
#include "GetTcpUdpData/GetTcpUdpState.h"
#include "GetProcFlows.h"
//_GetProcInfos@4
//_GetUdpTcp@8
#pragma comment(linker, "/EXPORT:GetProcInfos=_GetProcInfos@4")
#pragma comment(linker, "/EXPORT:GetUdpTcp=_GetUdpTcp@8")
#pragma comment(linker, "/EXPORT:GetProcFlowsInfos=_GetProcFlowsInfos@4")
#pragma comment(linker, "/EXPORT:LimitProcNet=_LimitProcNet@16")
#pragma comment(linker, "/EXPORT:CloseProcess=_CloseProcess@4")
#pragma comment(linker, "/EXPORT:JmpToFilePath=_JmpToFilePath@4")
#pragma comment(linker, "/EXPORT:LookAtFileProperties=_LookAtFileProperties@4")
#pragma comment(linker, "/EXPORT:EnableProDebugPrivilege=_EnableProDebugPrivilege@0")
#pragma comment(linker, "/EXPORT:OptimizeMem=_OptimizeMem@0")
#pragma comment(linker, "/EXPORT:GetLocalMachineInfos=_GetLocalMachineInfos@4")
#pragma comment(linker, "/EXPORT:GetSysRuntime=_GetSysRuntime@4")
#pragma comment(linker, "/EXPORT:ClearProcFlows=_ClearProcFlows@0")

	
	
//获取进程相关信息
 void   __stdcall GetProcInfos(PPROCINFOMAP * pProInfoList)
{
	CGetProcInfo::GetInstance()->GetProcInfo(pProInfoList);
}

 BOOL __stdcall EnableProDebugPrivilege()
 { 
	return EnableDebugPrivilege();
 }
//获取系统网络连接
 void   __stdcall GetUdpTcp(PTCPVECTOR * tcpvector,PUDPVECTOR * udpvector)
 {
	 CGetTcpUdpState::GetInstance()->GetAllNetConStatus(tcpvector,udpvector);
 }
 //获取系统进程流量网速
 BOOL __stdcall GetProcFlowsInfos(PPROCFLOWINFOMAP * ppprocflowmap)
 {
	 return CGetProcFlows::GetInstance()->GetProcFlows(ppprocflowmap);
 }
 BOOL   __stdcall LimitProcNet(ULONG pid,BOOL bLimit,LONG ulLimiDown /*= -1*/,LONG ulLimitUp /*= -1*/)
 {
	 return CGetProcFlows::GetInstance()->LimitProcSpeed(pid,bLimit,ulLimiDown,ulLimitUp);
	 
 }
 BOOL __stdcall ClearProcFlows()
 {
	  return CGetProcFlows::GetInstance()->ClearProcFlow();
 }
DWORD __stdcall CloseProcess(DWORD dwPid)
{
	HANDLE h = OpenProcess(PROCESS_TERMINATE ,FALSE,dwPid);
	if(!h)
	{
		return GetLastError();
	}
	TerminateProcess(h,0);
	return GetLastError();
}

void __stdcall JmpToFilePath(WCHAR * filepath)
{
	FindFile(filepath);
}

void __stdcall LookAtFileProperties(WCHAR * filepath)
{
	LookFileProperties(filepath);
}

LONGLONG __stdcall OptimizeMem()
{
	return OptimizeMemory();
}
void  __stdcall GetLocalMachineInfos(PUSERINFO * uinfo)
{
	GetLocalMachineInfo(uinfo);
}

void __stdcall GetSysRuntime(WCHAR * pTime)
{
	GetSystemRuntime(pTime);
}