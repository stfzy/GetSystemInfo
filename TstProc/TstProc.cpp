// TstProc.cpp : 定义控制台应用程序的入口点。
//
 
#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>
#include "../GetSystemInfo/impl.h"
#include <Psapi.h>
#include "ContrlNetSpeed.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"Psapi.lib")
//void GetProcInfos(PPROCINFOMAP pProInfoList)
typedef void (__stdcall *GPI)(PTCPVECTOR * tcpvector,PUDPVECTOR * udpvector);
typedef void (__stdcall *_GetProcInfos)(PPROCINFOMAP * pProInfoList);
GPI GetProcInfos = NULL;
_GetProcInfos _GetProcInfos1 = NULL;
TCPVECTOR * tcp;
UDPVECTOR * udp;
LPCTSTR GetProcessUserName(DWORD dwID)     // 进程ID 
{ 
	HANDLE hProcess=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,dwID); 
	if( hProcess==NULL ) 
		return NULL;

	HANDLE hToken    =NULL; 
	BOOL bResult    =FALSE; 
	DWORD dwSize    =0;

	static TCHAR szUserName[256]={0}; 
	TCHAR szDomain[256]={0}; 
	DWORD dwDomainSize=256; 
	DWORD dwNameSize=256;

	SID_NAME_USE    SNU; 
	PTOKEN_USER pTokenUser=NULL; 
	__try 
	{ 
		if( !OpenProcessToken(hProcess,TOKEN_QUERY,&hToken) ) 
		{ 
			bResult = FALSE; 
			__leave; 
		}

		if( !GetTokenInformation(hToken,TokenUser,pTokenUser,dwSize,&dwSize) ) 
		{ 
			if( GetLastError() != ERROR_INSUFFICIENT_BUFFER ) 
			{ 
				bResult = FALSE ; 
				__leave; 
			} 
		}

		pTokenUser = NULL; 
		pTokenUser = (PTOKEN_USER)malloc(dwSize); 
		if( pTokenUser == NULL ) 
		{ 
			bResult = FALSE; 
			__leave; 
		}

		if( !GetTokenInformation(hToken,TokenUser,pTokenUser,dwSize,&dwSize) ) 
		{ 
			bResult = FALSE; 
			__leave; 
		}

		if( LookupAccountSid(NULL,pTokenUser->User.Sid,szUserName,&dwNameSize,szDomain,&dwDomainSize,&SNU) != 0 ) 
		{ 
			return szUserName; 
		} 
	} 
	__finally 
	{ 
		if( pTokenUser!=NULL ) 
			free(pTokenUser); 
	}

	return NULL; 
}
DWORD __stdcall ThreadTexe(LPVOID lpThreadParameter)
{
	HMODULE h = LoadLibraryA("GetSystemInfo.dll");

	_GetProcInfos1 = (_GetProcInfos)GetProcAddress(h,"GetProcInfos");
	PROCINFOMAP * p;  

	do 
	{
		system("cls");
		_GetProcInfos1(&p);
		map<DWORD, ProcInfo>::iterator it;
		for (it = (*p).begin(); it != (*p).end(); it++)
		{
			wprintf(L"[ %ws ][ %ws ] [%d %%]\r\n", it->second.szProName,it->second.szFullPath ,it->second.iMemUsage);
		}	
		Sleep(1000);
	} while (TRUE);

	
	return 0;
}
void DebugPrivilege2()
{
	PHANDLE pTokenHandle=new HANDLE;    //令牌指针
	TOKEN_PRIVILEGES tkp;
	ZeroMemory(&tkp,sizeof(TOKEN_PRIVILEGES));
	//获取访问令牌       进程句柄            修改令牌                               令牌指针
	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,pTokenHandle))
	{
		delete pTokenHandle;
		return;
	}
	//查询权限标识           本机  seDebug      TOKEN_PRIVILEGES
	if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tkp.Privileges[0].Luid))
	{
		delete pTokenHandle;
		return;
	}
	tkp.PrivilegeCount=1;
	tkp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	//修改权限                令牌            修改 权限 旧权限的长度及结构        实际返回大小
	if(!AdjustTokenPrivileges(*pTokenHandle,FALSE,&tkp,0,(PTOKEN_PRIVILEGES)NULL,0))
	{
		delete pTokenHandle;
		return;
	}

}BOOL IsVistaAndLater()
{
	DWORD dwVersion, dwMajorVersion, dwMinorVersion;

	dwVersion = GetVersion(); 

	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	if(dwMajorVersion>=6)
		return TRUE;
	return FALSE;
}

DWORD  GetProcessUseMemory(DWORD dwProcID)
{ 
	if(dwProcID == 0)
		return 4*1024;
	
	HANDLE hProcess ;
	
	if(IsVistaAndLater())
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, dwProcID);
	else
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,dwProcID);
	
	PERFORMANCE_INFORMATION performanceInfo;
	
	memset(&performanceInfo, 0, sizeof(performanceInfo));
	 
	
	if(!::GetPerformanceInfo(&performanceInfo, sizeof(performanceInfo)))
		return 0;
	
	DWORD pageSize = performanceInfo.PageSize;

	BOOL bRet = TRUE;
	PSAPI_WORKING_SET_INFORMATION workSetInfo;
	PBYTE pByte = NULL;
	PSAPI_WORKING_SET_BLOCK * pWorkSetBlock = workSetInfo.WorkingSetInfo;

	memset(&workSetInfo, 0, sizeof(workSetInfo));
	// 要求操作进程的权限：PROCESS_QUERY_INFORMATION and PROCESS_VM_READ
	// 第一次调用获取实际缓冲区大小
	bRet = ::QueryWorkingSet(hProcess, &workSetInfo, sizeof(workSetInfo));
	if(!bRet) // 调用失败
	{
		DWORD error = GetLastError();
		if( error == ERROR_BAD_LENGTH) // 需要重新分配缓冲区
		{
			DWORD realSize = sizeof(workSetInfo.NumberOfEntries) + workSetInfo.NumberOfEntries*sizeof(PSAPI_WORKING_SET_BLOCK); 
			pByte = new BYTE[realSize];
			
			memset(pByte, 0, realSize);
			pWorkSetBlock = (PSAPI_WORKING_SET_BLOCK *)(pByte + sizeof(workSetInfo.NumberOfEntries));
			
			// 重新获取
			if(!::QueryWorkingSet(hProcess, pByte, realSize))
			{
				delete[] pByte; // 清理内存
				CloseHandle(hProcess);
				return 0;
			}  
		}
		else // 其它错误，认为获取失败
		{ 
			PROCESS_MEMORY_COUNTERS promemcou;
			GetProcessMemoryInfo(hProcess,&promemcou,sizeof(promemcou));  
			CloseHandle(hProcess);
			return promemcou.WorkingSetSize;
		}
	}
	SIZE_T workSetPrivate = -4096;
	for (ULONG_PTR i = 0; i < workSetInfo.NumberOfEntries; ++i)
	{
		if(!pWorkSetBlock[i].Shared) // 如果不是共享页
			workSetPrivate += pageSize;
	}

	if(pByte)
		delete[] pByte;

	CloseHandle(hProcess);

	return workSetPrivate;
} 

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR            szDriveStr[500];
	TCHAR            szDrive[3];
	TCHAR            szDevName[100];
	INT                cchDevName;
	INT                i;

	//检查参数
	if(!pszDosPath || !pszNtPath )
		return FALSE;

	//获取本地磁盘字符串
	if(GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for(i = 0; szDriveStr[i]; i += 4)
		{
			if(!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if(!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if(_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}            
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

//获取进程完整路径
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH])
{
	TCHAR        szImagePath[MAX_PATH];
	HANDLE        hProcess;
	if(!pszFullPath)
		return FALSE;
 
	pszFullPath[0] = '\0';
	if(IsVistaAndLater())
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, dwPID);
	else
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,dwPID);
	if(!hProcess)
		return FALSE;

	
	DWORD dwSize = MAX_PATH;
	if(!QueryFullProcessImageName(hProcess,PROCESS_NAME_NATIVE,szImagePath,&dwSize))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	if(!DosPathToNtPath(szImagePath, pszFullPath))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwSize = sizeof(ProcessFlow);
	
	ProcessFlow ProcessesFlow[2048];//用来获取进程流量


 
// 	DebugPrivilege2();
// 	TCHAR sdf[260];
// 	 GetProcessFullPath(4948,sdf);
	 DebugPrivilege2();
// 	 CreateThread(0,0,ThreadTexe,0,0,0);
//  
// 	 getchar();
	HANDLE hsnap=::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	
	if(INVALID_HANDLE_VALUE==hsnap)
	 {
		  
		 return 0;
	 }
	 else
	 {
		 
		 PROCESSENTRY32 pe;
		 pe.dwSize=sizeof(PROCESSENTRY32);
		 int b=::Process32First(hsnap,&pe);
		 while(b)
		 {
			 DWORD dwUsg = GetProcessUseMemory(pe.th32ProcessID);
			 TCHAR sdf[260];   
			 GetProcessFullPath(pe.th32ProcessID,sdf); 
			 wprintf(_T("%s  %d   %d \r\n"),pe.szExeFile,pe.th32ProcessID,dwUsg);
			 b=::Process32Next(hsnap,&pe);
		 }

	 }

	 ::CloseHandle(hsnap);
	 getchar();
	return 0;
}

