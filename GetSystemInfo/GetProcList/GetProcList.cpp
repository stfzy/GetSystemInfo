#include "stdafx.h"
#include "GetProcList.h"
#include <tlhelp32.h>
#include <Shlwapi.h>
#pragma comment(lib,"shlwapi.lib")

CGetProcList::CGetProcList(void)
{
	m_processor_count_ = get_processor_number();
}


CGetProcList::~CGetProcList(void)
{
}


BOOL CGetProcList::GetProcList(PPROCINFOMAP prolist, BYTE * pHave)
{
	static BYTE bHave = 0;
	BOOL bRet = FALSE;
	HANDLE hsnap=::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(INVALID_HANDLE_VALUE==hsnap)
	{		 
		return bRet;
	}
	else
	{
		
		PROCESSENTRY32 pe;
		pe.dwSize=sizeof(PROCESSENTRY32);
		int b=::Process32First(hsnap,&pe);
		while(b)
		{
			 
			if((*prolist)[pe.th32ProcessID].pid == 0||_tcscmp((*prolist)[pe.th32ProcessID].szProName,pe.szExeFile)!=0 )
			{
				ProcInfo proinfo;
				proinfo.pid = pe.th32ProcessID;
				_tcscpy_s(proinfo.szProName, pe.szExeFile);

				GetProcessFullPath(proinfo.pid,proinfo.szFullPath);//获取全路径
				GetFileDescription(proinfo.szFullPath,proinfo.szProExplain); //获取文件描述

				proinfo.hpro = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ , FALSE, (DWORD)proinfo.pid);//获取进程句柄
				(*prolist)[pe.th32ProcessID] = proinfo;
				
				//prolist->push_back(proinfo);
			}
		
			(*prolist)[pe.th32ProcessID].bBl = bHave;
			
			b=::Process32Next(hsnap,&pe);

		}
		bRet = TRUE;

	}

 
	bHave ^= 1;
	*pHave = bHave;
	::CloseHandle(hsnap);
	return bRet;
}

BOOL CGetProcList::GetProcList2(PPROCINFOMAP * promap, BYTE * pHave)
{
 
	static BYTE bHave = 0;
	PSYSTEM_PROCESSES  pSystemProc;
	
	HMODULE            hNtDll = NULL;
	LPVOID             lpSystemInfo = NULL;
	DWORD              dwNumberBytes = MAX_INFO_BUF_LEN;
	DWORD              dwTotalProcess = 0;
	DWORD              dwReturnLength;
	NTSTATUS           Status;
	LONGLONG           system_time,time;
	FILETIME           now;
	__try
	{
		hNtDll = LoadLibrary(L"NtDll.dll");
		if (hNtDll == NULL)
		{
			 
			__leave;
		}

		NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");
		if (NtQuerySystemInformation == NULL)
		{
		 
			__leave;
		}

		lpSystemInfo = (LPVOID)malloc(dwNumberBytes);
		Status = NtQuerySystemInformation(NT_PROCESSTHREAD_INFO,
			lpSystemInfo,
			dwNumberBytes,
			&dwReturnLength);
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{ 
			__leave;
		}
		else if (Status != STATUS_SUCCESS)
		{ 
			__leave;
		}
  		 
		pSystemProc = (PSYSTEM_PROCESSES)lpSystemInfo;
		while (pSystemProc)
		{
			
			if (m_ProInfos[pSystemProc->ProcessId].pid == 0 && *m_ProInfos[pSystemProc->ProcessId].szProName == 0)
			{ 
				ProcInfo proinfo;
				proinfo.pid = pSystemProc->ProcessId;
				
				//pSystemProc->Threads->State ;  //主线程状态
				
				if (proinfo.pid == 0)
				{
					_tcscpy_s(proinfo.szProName, L"系统空闲进程"); 
				}
				else if(proinfo.pid == 4)
					_tcscpy_s(proinfo.szProName, L"系统和压缩内存"); 				
				else
					_tcscpy_s(proinfo.szProName, pSystemProc->ProcessName.Buffer);
				  
				//SysNative 64位 地址重定向
				//GetProcessFullPath(proinfo.pid, proinfo.szFullPath);//获取全路径
				//GetFileDescription(proinfo.szFullPath, proinfo.szProExplain); //获取文件描述
		 
				//proinfo.hpro = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)proinfo.pid);//获取进程句柄
				m_ProInfos[pSystemProc->ProcessId] = proinfo;
			}
			m_ProInfos[pSystemProc->ProcessId].bBl = bHave;
			if(m_ProInfos[pSystemProc->ProcessId].szFullPath[0] == 0)
			{
				GetProcessFullPath(m_ProInfos[pSystemProc->ProcessId].pid, m_ProInfos[pSystemProc->ProcessId].szFullPath);//获取全路径 
				 
				GetFileDescription(m_ProInfos[pSystemProc->ProcessId].szFullPath, m_ProInfos[pSystemProc->ProcessId].szProExplain); //获取文件描述
			}//mem
// 			if(IsVistaAndLater())
// 				m_ProInfos[pSystemProc->ProcessId].iMemUsage = GetProcMemFromPerformence(m_ProInfos[pSystemProc->ProcessId].szProName,pSystemProc->ProcessId);          //获取内存私有集
// 			else
				m_ProInfos[pSystemProc->ProcessId].iMemUsage = GetProcessUseMemory(pSystemProc->ProcessId);
			//m_ProInfos[pSystemProc->ProcessId].iMemUsage = pSystemProc->VmCounters.WorkingSetSize/* / 1024*/; //内存工作集
			//m_ProInfos[pSystemProc->ProcessId].iMemUsage = pSystemProc->VmCounters.PagefileUsage;
  
			//username
			  GetProcessUserName(pSystemProc->ProcessId, m_ProInfos[pSystemProc->ProcessId].szProcUserName);
			  
			if(!m_ProInfos[pSystemProc->ProcessId].hicoPro)
			//HICON
			{
				
				if(m_ProInfos[pSystemProc->ProcessId].szFullPath[0])
				{
			 
					m_ProInfos[pSystemProc->ProcessId].hicoPro = GetFileIcon(m_ProInfos[pSystemProc->ProcessId].szFullPath);

					//DeleteObject( m_ProInfos[pSystemProc->ProcessId].hicoPro ); 
				}
			}
	 

			//llTempTime = pSystemProc->KernelTime.QuadPart + pSystemProc->UserTime.QuadPart;
			/************************************************************************/
			/* cpu                                                                     */
			/************************************************************************/
			GetSystemTimeAsFileTime(&now);

			system_time = (pSystemProc->KernelTime.QuadPart + pSystemProc->UserTime.QuadPart) / m_processor_count_;
			time = file_time_2_utc(&now);

			if (m_ProInfos[pSystemProc->ProcessId].last_time_ == 0 && m_ProInfos[pSystemProc->ProcessId].last_system_time_ == 0)
			{
				m_ProInfos[pSystemProc->ProcessId].last_system_time_ = system_time;
				m_ProInfos[pSystemProc->ProcessId].last_time_ = time;

			}
			else
			{
				LONGLONG	system_time_delta = system_time - m_ProInfos[pSystemProc->ProcessId].last_system_time_;
				LONGLONG    time_delta = time - m_ProInfos[pSystemProc->ProcessId].last_time_;
 
				// We add time_delta / 2 so the result is rounded.
				m_ProInfos[pSystemProc->ProcessId].uiCpu = (int)((system_time_delta * 100 + time_delta / 2) / time_delta);

				m_ProInfos[pSystemProc->ProcessId].last_system_time_ = system_time;
				m_ProInfos[pSystemProc->ProcessId].last_time_ = time;
			}
			/************************************************************************/
			/* io                                                                     */
			/************************************************************************/
			LONGLONG readTran = pSystemProc->IoCounters.ReadTransferCount.QuadPart;
			LONGLONG writeTran = pSystemProc->IoCounters.WriteTransferCount.QuadPart;
			if (m_ProInfos[pSystemProc->ProcessId].idiskwritecount == 0 && m_ProInfos[pSystemProc->ProcessId].idiskreadcount== 0)
			{
				m_ProInfos[pSystemProc->ProcessId].idiskreadcount = readTran;
				m_ProInfos[pSystemProc->ProcessId].idiskwritecount =writeTran;
			}
			else
			{ 
				m_ProInfos[pSystemProc->ProcessId].iDiskRead = readTran - m_ProInfos[pSystemProc->ProcessId].idiskreadcount;
				m_ProInfos[pSystemProc->ProcessId].idiskreadcount = readTran;
				 
				m_ProInfos[pSystemProc->ProcessId].iDiskWrite =writeTran - m_ProInfos[pSystemProc->ProcessId].idiskwritecount;
				m_ProInfos[pSystemProc->ProcessId].idiskwritecount = writeTran; 
			}
			nexte:
			if (pSystemProc->NextEntryDelta == 0)
				break;
			pSystemProc = (PSYSTEM_PROCESSES)((char *)pSystemProc + pSystemProc->NextEntryDelta);
		}
	 
	}
	__finally
	{
		if (lpSystemInfo != NULL)
		{ 
			free(lpSystemInfo);
		}
		if (hNtDll != NULL)
		{
			FreeLibrary(hNtDll);
		}
		*promap = &m_ProInfos;
		bHave ^= 1;
		*pHave = bHave;
	}

	return 0;
}
