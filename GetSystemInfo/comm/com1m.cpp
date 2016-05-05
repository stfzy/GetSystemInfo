#include "stdafx.h"
#include "comm.h"
#include "../impl.h"
#include "../GetProcInfos.h"
#include <crtdbg.h>
#include <TlHelp32.h>
#include <Pdh.h>
#include <tlhelp32.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <IPHlpApi.h>
#include <iostream>
#include <wininet.h>
#include <vector>
#include <Shlwapi.h>
#include <winver.h>
#include <mmsystem.h>
using namespace std;
#pragma comment(lib,"wininet.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib,"IPHlpApi.lib")
#pragma comment(lib,"SHLWAPI.lib")
#pragma comment(lib,"pdh.lib")


int GetProcMemFromPerformence(WCHAR* pProcName,DWORD dwProId)
{
	HQUERY hQuery = NULL ;
	PDH_STATUS pdhStatus ;
	HCOUNTER  pCounterHandle = NULL ;

	if(dwProId == 0)
		return 1024*4;
	pdhStatus = PdhOpenQuery (0 ,0, &hQuery);
	if ( pdhStatus != ERROR_SUCCESS )
	{
		return 0;
	}

	PDH_FMT_COUNTERVALUE fmtValue ;
	DWORD dwctrType ;

	WCHAR str[256],szProname[260],szProNameTmp[260];
	int i = 0;

	ZeroMemory(szProname,260);
	ZeroMemory(szProNameTmp,260);
	
	wcscat_s(szProname,pProcName);
	WCHAR * dotP = wcsrchr(szProname,L'.');
	if(dotP)
	{
		ZeroMemory(dotP,wcslen(dotP));
	}
	 wcscat_s(szProNameTmp,szProname);

	wsprintfW(str,L"\\Process(%s)\\ID Process",szProname);	

	pdhStatus = PdhAddCounterW( hQuery, str, 0,&pCounterHandle);

	if ( pdhStatus == ERROR_SUCCESS )
	{
		do 
		{
			pdhStatus = PdhCollectQueryData ( hQuery ) ;
			if ( pdhStatus == ERROR_SUCCESS )
			{
				//�õ���ǰ������ֵ����
				pdhStatus = PdhGetFormattedCounterValue (  pCounterHandle , PDH_FMT_DOUBLE , & dwctrType , & fmtValue ) ;
				if ( pdhStatus != ERROR_SUCCESS )
				{
					return 0;
				}
				else
				{

					if(fmtValue.doubleValue == dwProId) 
					{
						break;
					}
					else
					{
						PdhRemoveCounter(pCounterHandle);
						ZeroMemory(szProname,260); 
						wsprintfW(szProname,L"%s#%d",szProNameTmp,++i); 
						wsprintfW(str,L"\\Process(%s)\\ID Process",szProname); 
						pdhStatus = PdhAddCounterW( hQuery, str, 0,&pCounterHandle);
						if(pdhStatus !=ERROR_SUCCESS)
							return 0;
					}
				}

			}
			else
				return 0;

		} 
		while (1);
	} 
	PdhRemoveCounter(pCounterHandle);
	wsprintfW(str,L"\\Process(%s)\\Working Set - Private",szProname);	

	pdhStatus = PdhAddCounterW( hQuery, str, 0,&pCounterHandle);

	if ( pdhStatus == ERROR_SUCCESS )
	{ 
		do 
		{
			pdhStatus = PdhCollectQueryData ( hQuery ) ;
			if ( pdhStatus == ERROR_SUCCESS )
			{ 
				pdhStatus = PdhGetFormattedCounterValue (  pCounterHandle , PDH_FMT_DOUBLE , & dwctrType , & fmtValue ) ;
				if ( pdhStatus != ERROR_SUCCESS )
				{
					return 0;
				}
				else
				{
					break; 
				}

			}
			else
				return 0;

		} 
		while (0);
	}
	PdhRemoveCounter(pCounterHandle);
	pdhStatus = PdhCloseQuery (hQuery );
	return fmtValue.doubleValue;
}


DWORD  GetProcessUseMemory(DWORD dwProcID)
{ 
	HANDLE hProcess;
	//���id��4����ô����4
	if(dwProcID == 0)
		return 4*1024;

	if(IsVistaAndLater())
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, dwProcID);
	else
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,dwProcID);

	/*��ʱֻ��ȡ�������ڴ�*/
	PROCESS_MEMORY_COUNTERS promemcou;
	GetProcessMemoryInfo(hProcess,&promemcou,sizeof(promemcou)); 
	CloseHandle(hProcess);
	return promemcou.WorkingSetSize;
	/*��ʱֻ��ȡ�������ڴ�*/


	PERFORMANCE_INFORMATION performanceInfo;
	memset(&performanceInfo, 0, sizeof(performanceInfo));
	if(!::GetPerformanceInfo(&performanceInfo, sizeof(performanceInfo)))
		return 0;

	DWORD pageSize = performanceInfo.PageSize;

	BOOL bRet = TRUE;
	PSAPI_WORKING_SET_INFORMATION workSetInfo;
	PBYTE pByte = NULL;
	PSAPI_WORKING_SET_BLOCK *pWorkSetBlock = workSetInfo.WorkingSetInfo;
	memset(&workSetInfo, 0, sizeof(workSetInfo));
	// Ҫ��������̵�Ȩ�ޣ�PROCESS_QUERY_INFORMATION and PROCESS_VM_READ
	// ��һ�ε��û�ȡʵ�ʻ�������С
	bRet = ::QueryWorkingSet(hProcess, &workSetInfo, sizeof(workSetInfo));
	if(!bRet) // ����ʧ��
	{
		if(GetLastError() == ERROR_BAD_LENGTH) // ��Ҫ���·��仺����
		{
			DWORD realSize = sizeof(workSetInfo.NumberOfEntries) 
				+ workSetInfo.NumberOfEntries*sizeof(PSAPI_WORKING_SET_BLOCK);

			pByte = new BYTE[realSize];
			memset(pByte, 0, realSize);
			pWorkSetBlock = (PSAPI_WORKING_SET_BLOCK *)(pByte + sizeof(workSetInfo.NumberOfEntries));
			// ���»�ȡ
			if(!::QueryWorkingSet(hProcess, pByte, realSize))
			{
				delete[] pByte; // �����ڴ�
				CloseHandle(hProcess);
				return 0;
			} 

		}
		else // ����������Ϊ��ȡʧ��
		{
			PROCESS_MEMORY_COUNTERS promemcou;
			GetProcessMemoryInfo(hProcess,&promemcou,sizeof(promemcou)); 
			CloseHandle(hProcess);
			return promemcou.WorkingSetSize;
			
			
		}
	}
	SIZE_T workSetPrivate = 0;
	for (ULONG_PTR i = 0; i < workSetInfo.NumberOfEntries; ++i)
	{
		if(!pWorkSetBlock[i].Shared) // ������ǹ���ҳ
			workSetPrivate += pageSize;
	}

	if(pByte)
		delete[] pByte;

	CloseHandle(hProcess);

	return workSetPrivate;
} 
BOOL GetProcName(DWORD pid,LPWSTR szProName)
{
	HANDLE hsnap=::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(INVALID_HANDLE_VALUE==hsnap)
	{ 
		return FALSE;
	}
	else
	{
		PROCESSENTRY32 pe;
		pe.dwSize=sizeof(PROCESSENTRY32);
		int b=::Process32First(hsnap,&pe);
		while(b)
		{
			if(pid == pe.th32ProcessID)
			{
				wcscpy_s(szProName,260,pe.szExeFile);
				break;
			}

			b=::Process32Next(hsnap,&pe);
		}

	}

	::CloseHandle(hsnap);

	return TRUE;
}

BOOL GetProcessUserName(DWORD dwID, LPWSTR szUserName)
{ 
	HANDLE hProcess;
	if(IsVistaAndLater())
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, dwID);
	else
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,dwID);

 
	if( hProcess==NULL ) 
	{
		wcscpy_s(szUserName ,MAX_PATH,L"SYSTEM");

		//����޷��򿪽��̣���win10 ��Ϊ��ϵͳ����
		return FALSE;
	}

	HANDLE hToken    =NULL; 
	BOOL bResult    =FALSE; 
	DWORD dwSize    =0;

	//static TCHAR szUserName[256]={0}; 
	TCHAR szDomain[256]={0}; 
	DWORD dwDomainSize=256; 
	DWORD dwNameSize=256;

	SID_NAME_USE    SNU; 
	PTOKEN_USER pTokenUser=NULL; 
	__try 
	{ 
		if( !OpenProcessToken(hProcess,TOKEN_QUERY,&hToken) ) 
		{ 
			 
			__leave; 
		}

		if( !GetTokenInformation(hToken,TokenUser,pTokenUser,dwSize,&dwSize) ) 
		{ 
			if( GetLastError() != ERROR_INSUFFICIENT_BUFFER ) 
			{ 
				 
				__leave; 
			} 
		}

		pTokenUser = NULL; 
		pTokenUser = (PTOKEN_USER)malloc(dwSize); 
		if( pTokenUser == NULL ) 
		{  
			__leave; 
		}

		if( !GetTokenInformation(hToken,TokenUser,pTokenUser,dwSize,&dwSize) ) 
		{ 
		 
			__leave; 
		}

		if( LookupAccountSid(NULL,pTokenUser->User.Sid,(LPWSTR)szUserName,&dwNameSize,szDomain,&dwDomainSize,&SNU) != 0 ) 
		{ 
			  bResult = TRUE;
		}
	} 
	__finally 
	{ 
		if( pTokenUser!=NULL ) 
			free(pTokenUser); 
		if(hProcess)
			CloseHandle(hProcess);
		if(hToken)
			CloseHandle(hToken);
	}
	if(!bResult)
	{
		wcscpy_s(szUserName ,MAX_PATH,L"SYSTEM");
			 
	}
	return bResult; 
}

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR            szDriveStr[500];
	TCHAR            szDrive[3];
	TCHAR            szDevName[100];
	INT                cchDevName;
	INT                i;

	//������
	if(!pszDosPath || !pszNtPath )
		return FALSE;

	//��ȡ���ش����ַ���
	if(GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for(i = 0; szDriveStr[i]; i += 4)
		{
			if(!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if(!QueryDosDevice(szDrive, szDevName, 100))//��ѯ Dos �豸��
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if(_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//����
			{
				lstrcpy(pszNtPath, szDrive);//����������
				lstrcat(pszNtPath, pszDosPath + cchDevName);//����·��

				return TRUE;
			}            
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

void GetFileDescription(TCHAR* filepath,WCHAR* pfiledesc)
{
	if(filepath == NULL||_tcscmp(filepath,_T(""))==0)return;
	DWORD dwSize = GetFileVersionInfoSize(filepath, NULL);
	WCHAR * pBuf = NULL;
	pBuf = new WCHAR[dwSize + sizeof(WCHAR)];
	WCHAR* lpBuffer = NULL;
	 
	GetFileVersionInfo(filepath, NULL, dwSize, pBuf);
	lpBuffer = pBuf;
	do 
	{
		 
		lpBuffer = (WCHAR*)memchr(lpBuffer, 0x46, dwSize);
		if(lpBuffer==NULL)break;
		if (wcscmp(L"FileDescription", (WCHAR*)lpBuffer) == 0)
		{
			lpBuffer += wcslen((PWCHAR)lpBuffer);
			lpBuffer+=2;

			break;
		}

		lpBuffer++;
	/*	Sleep(1);*/
	} while (TRUE);
	if(lpBuffer)
		wcscpy_s(pfiledesc,260,lpBuffer);
	delete pBuf;
}
void DebugPrivilege2()
{
	 PHANDLE pTokenHandle=new HANDLE;    //����ָ��
    TOKEN_PRIVILEGES tkp;
    ZeroMemory(&tkp,sizeof(TOKEN_PRIVILEGES));
    //��ȡ��������       ���̾��            �޸�����                               ����ָ��
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,pTokenHandle))
    {
		delete pTokenHandle;
        return;
    }
    //��ѯȨ�ޱ�ʶ           ����  seDebug      TOKEN_PRIVILEGES
    if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tkp.Privileges[0].Luid))
	{
		delete pTokenHandle;
        return;
    }
    tkp.PrivilegeCount=1;
    tkp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    //�޸�Ȩ��                ����            �޸� Ȩ�� ��Ȩ�޵ĳ��ȼ��ṹ        ʵ�ʷ��ش�С
    if(!AdjustTokenPrivileges(*pTokenHandle,FALSE,&tkp,0,(PTOKEN_PRIVILEGES)NULL,0))
	{
		delete pTokenHandle;
        return;
    }

}

 
bool AdjustPrivileges()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    TOKEN_PRIVILEGES oldtp;
    DWORD dwSize=sizeof(TOKEN_PRIVILEGES);
    LUID luid;
 
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (GetLastError()==ERROR_CALL_NOT_IMPLEMENTED) return true;
        else return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount=1;
    tp.Privileges[0].Luid=luid;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    /* Adjust Token Privileges */
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwSize)) {
        CloseHandle(hToken);
        return false;
    }
    // close handles
    CloseHandle(hToken);
    return true;
}
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

void DebugPrivilege()
 {
  HANDLE hToken = NULL;
  //�򿪵�ǰ���̵ķ�������
  int hRet = OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,&hToken);

 if( hRet)
  {
   TOKEN_PRIVILEGES tp;
   tp.PrivilegeCount = 1;
   //ȡ������Ȩ�޵�LUID
   LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid);
   tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
   //�����������Ƶ�Ȩ��
   AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);

  CloseHandle(hToken);
  }
 }

//��ȡ��������·��
BOOL GetProcessFullPath(DWORD dwPID, TCHAR * pszFullPath)
{
	TCHAR        szImagePath[MAX_PATH];
	HANDLE       hProcess;
	if(!pszFullPath)
		return FALSE;
 
	pszFullPath[0] = '\0';
	//�ж��ǲ���VISTA
	if(IsVistaAndLater())
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, dwPID);
	else
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,dwPID);


	if(!hProcess)
	{ 
		return FALSE;
	}
	if(!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
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


/// ���CPU�ĺ���
 int get_processor_number()
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	return (int)info.dwNumberOfProcessors;
}

/// ʱ��ת��
 LONGLONG file_time_2_utc(const FILETIME* ftime)
{
	LARGE_INTEGER li;

	 
	li.LowPart = ftime->dwLowDateTime;
	li.HighPart = ftime->dwHighDateTime;
	return li.QuadPart;
}

 HICON GetFileIcon(LPCTSTR lpFileName)
 {
 
	 SHFILEINFO sfi = {0};
	 DWORD_PTR dwRet = SHGetFileInfo(lpFileName, NULL, &sfi, sizeof(SHFILEINFO), SHGFI_SMALLICON|SHGFI_ICON);
 
	 return (dwRet != 0) ? sfi.hIcon : NULL;
 }
 BOOL IsVistaAndLater()
 {
	 DWORD dwVersion, dwMajorVersion, dwMinorVersion;
	  
	 dwVersion = GetVersion(); 

	 dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	 dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	 if(dwMajorVersion>=6)
		 return TRUE;
	 return FALSE;
 }
 void LookFileProperties(TCHAR* filepath)
 {
	 if (*filepath == 0)
		 return;
	 
	 SHELLEXECUTEINFO se;
	 ZeroMemory(&se, sizeof(se));
	 se.cbSize = sizeof(se);
	 se.lpFile = filepath; // �˴���֤��ȷ
	 se.lpVerb = _T("properties");
	 se.fMask = SEE_MASK_INVOKEIDLIST;
	 ::ShellExecuteEx(&se);
	  
 }
typedef BOOL (WINAPI *_Wow64DisableWow64FsRedirection )(__out PVOID *OldValue);
typedef	BOOL (WINAPI*_Wow64RevertWow64FsRedirection) (__in PVOID OlValue );


 void FindFile(TCHAR* filepath)
 {
	 if (*filepath == 0)
		 return;
	 _Wow64DisableWow64FsRedirection wdis;
	 _Wow64RevertWow64FsRedirection wrev ;
	 PVOID p;
	 HMODULE h = LoadLibrary(_T("Kernel32.dll"));
	 wdis = (_Wow64DisableWow64FsRedirection )GetProcAddress(h,"Wow64DisableWow64FsRedirection");
	 wrev = (_Wow64RevertWow64FsRedirection )GetProcAddress(h,"Wow64RevertWow64FsRedirection");
	 FreeLibrary(h);
	 if(wdis)
		 wdis(&p);
	 SHELLEXECUTEINFO shex = { 0 };
	 shex.cbSize = sizeof(SHELLEXECUTEINFO);
	 shex.lpFile = _T("explorer");
	 TCHAR tpath[MAX_PATH] = { 0 };
	 _tcscpy_s(tpath, _T(" /select, "));
	 _tcscat_s(tpath, filepath);
	 shex.lpParameters = tpath;
	 shex.lpVerb = _T("open");
	 shex.nShow = SW_SHOWDEFAULT;
	 shex.lpDirectory = NULL;
	 ShellExecuteEx(&shex);
	 if(wrev)
		wrev(p);

 }

 void   GetSystemRuntime(WCHAR * pTime)
 { 
	 ULONGLONG ull = GetTickCount64();
	 ULONGLONG s= ull/1000;
	 int second=s%60;
	 int minute=s/60%60;
	 int hour=s/60/60%24;
	 int day = s/60/60/24;
	 wsprintfW (pTime,L"ϵͳ������%d��%dСʱ%d��%d��",day,hour,minute,second); 

 }

/** video card and OS */
bool GetUserInfo(USERINFO& Info)
{
    HRESULT hres;
 
    hres =  CoInitialize( NULL );
    if (FAILED(hres))
    {
        return false;                
    }
 
    hres =  CoInitializeSecurity(
        NULL,
        -1,                         
        NULL,                       
        NULL,                       
        RPC_C_AUTHN_LEVEL_DEFAULT,  
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,                       
        EOAC_NONE,                  
        NULL                        
        );
 
 
    if (FAILED(hres))
    {
        CoUninitialize();
        return false;                  
    }
 
    IWbemLocator *pLoc = NULL;
 
    hres = CoCreateInstance(
        CLSID_WbemLocator,            
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres))
    {
        CoUninitialize();
        return false;                
    }
 
    IWbemServices *pSvc = NULL;
 
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),//CIMV2"),
        NULL,                   
        NULL,                   
        0,                      
        NULL,                   
        0,                      
        0,                      
        &pSvc                   
        );
 
    if (FAILED(hres))
    {
        pLoc->Release();    
        CoUninitialize();
        return false;              
    }
 
    hres = CoSetProxyBlanket(
        pSvc,                       
        RPC_C_AUTHN_WINNT,          
        RPC_C_AUTHZ_NONE,           
        NULL,                       
        RPC_C_AUTHN_LEVEL_CALL,     
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,                       
        EOAC_NONE                   
        );
 
    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();    
        CoUninitialize();
        return false;              
    }

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_ComputerSystem"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;              
	}

	IWbemClassObject *pclsObj;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;
		
		hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);    
	    wcscpy_s(Info.szModel,MAX_PATH,vtProp.bstrVal); 
		wcscat_s(Info.szModel,MAX_PATH,L" ");

		VariantClear(&vtProp);
		hr = pclsObj->Get(L"Model", 0, &vtProp, 0, 0);  
		wcscat_s(Info.szModel,MAX_PATH,vtProp.bstrVal); 
		VariantClear(&vtProp);
		 
		pclsObj->Release();
	}

	pEnumerator->Release();
	pEnumerator=NULL;

 
   
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);
 
    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;              
    }
 
    
    
 
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);
 
        if(0 == uReturn)
        {
            break;
        }
 
        VARIANT vtProp;
  
        hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);  //os
        //vtProp.bstrVal is what you need.
		wcscpy_s(Info.szOperatingSystem,MAX_PATH,vtProp.bstrVal);
		wcscat_s(Info.szOperatingSystem,MAX_PATH,L" (Build ");
 
        VariantClear(&vtProp);
        hr = pclsObj->Get(L"BuildNumber", 0, &vtProp, 0, 0); // example "10586"
		wcscat_s(Info.szOperatingSystem,MAX_PATH,vtProp.bstrVal);
		wcscat_s(Info.szOperatingSystem,MAX_PATH,L") ");
        
		VariantClear(&vtProp);
        hr = pclsObj->Get(L"OSArchitecture", 0, &vtProp, 0, 0); // example x64
		wcscat_s(Info.szOperatingSystem,MAX_PATH,vtProp.bstrVal);
        
		VariantClear(&vtProp);
		hr = pclsObj->Get(L"InstallDate", 0, &vtProp, 0, 0); // example x64
		WCHAR szYear[5],szMon[3],szDay[3],szHour[3],szMin[3],szSec[3];
		BSTR bTmp = vtProp.bstrVal; 
		wcsncpy_s(szYear,5,bTmp,4);bTmp+=4;
		wcsncpy_s(szMon,3,bTmp,2);bTmp+=2;
		wcsncpy_s(szDay,3,bTmp,2);bTmp+=2;
		wcsncpy_s(szHour,3,bTmp,2);bTmp+=2;
		wcsncpy_s(szMin,3,bTmp,2);bTmp+=2;
		wcsncpy_s(szSec,3,bTmp,2);bTmp+=2;
		wsprintfW(Info.szSystemInstallTime,L"%s��%s��%s�� %s:%s:%s",szYear,szMon,szDay,szHour,szMin,szSec);

		hr = pclsObj->Get(L"LastBootUpTime", 0, &vtProp, 0, 0); // example x64
		 
		bTmp = vtProp.bstrVal; 
		wcsncpy_s(szYear,5,bTmp,4);bTmp+=4;
		wcsncpy_s(szMon,3,bTmp,2);bTmp+=2;
		wcsncpy_s(szDay,3,bTmp,2);bTmp+=2;
		wcsncpy_s(szHour,3,bTmp,2);bTmp+=2;
		wcsncpy_s(szMin,3,bTmp,2);bTmp+=2;
		wcsncpy_s(szSec,3,bTmp,2);bTmp+=2;
		wsprintfW(Info.szBootTime,L"%s��%s��%s�� %s:%s:%s",szYear,szMon,szDay,szHour,szMin,szSec);
        pclsObj->Release();
    }
     
    pEnumerator->Release();
    pEnumerator=NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_VideoController"),		
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);
 
    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;              
    }
 
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);
 
        if(0 == uReturn)
        {
            break;
        }
 
        VARIANT vtProp,vtProp2; 
		WCHAR szTmp[MAX_PATH]={0};
		hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);  //video desc 
        hr = pclsObj->Get(L"AdapterRAM",0,&vtProp2,0,0);
		wsprintfW(szTmp,L"%s (%d MB)",vtProp.bstrVal,vtProp2.llVal /1024 / 1024);
	 
		Info.vcDisplayCard.push_back(szTmp);
		VariantClear(&vtProp);
		VariantClear(&vtProp2);
		
		
		pclsObj->Release();
    }
 
    pEnumerator->Release();
    pEnumerator=NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_Processor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);
 
    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;              
    }
 
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);
 
        if(0 == uReturn)
        {
            break;
        }
 
        VARIANT vtProp,vtProp1;
 
        hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
		hr = pclsObj->Get(L"NumberOfCores", 0, &vtProp1, 0, 0);
		wsprintfW(Info.szCpu,L"%s ��������%d",vtProp.bstrVal,vtProp1.iVal);
		VariantClear(&vtProp);
		VariantClear(&vtProp1);


        pclsObj->Release();
    }

	pEnumerator->Release();
	pEnumerator=NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_DiskDrive"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;              
	}

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			break;
		}

		VARIANT vtProp,vtProp1,vtProp2;
		DISKINFO diskInfo;	
		hr = pclsObj->Get(L"PNPDeviceID", 0, &vtProp, 0, 0);
		wcscpy_s(diskInfo.szName,MAX_PATH,vtProp.bstrVal);
		VariantClear(&vtProp);
	     
		hr = pclsObj->Get(L"Size", 0, &vtProp, 0, 0);  //video desc
		 
		hr = pclsObj->Get(L"Caption", 0, &vtProp1, 0, 0);  //video des 
		hr = pclsObj->Get(L"SerialNumber", 0, &vtProp2, 0, 0);  //video desc
		wsprintfW(diskInfo.szInfo,L"%s(%d GB)  ���кţ�	",vtProp1.bstrVal,_wtoi64(vtProp.bstrVal)/1000/1000/1000);
		BSTR bTmp = vtProp2.bstrVal;
		do 
		{
			if(*bTmp == L' ')
				bTmp++;
			else
				break;
		} while (TRUE);
		wcscat_s(diskInfo.szInfo,MAX_PATH,bTmp);
		Info.vcDiskInfo.push_back(diskInfo);

		VariantClear(&vtProp);
		VariantClear(&vtProp1);
		VariantClear(&vtProp2);
		pclsObj->Release();
	}
	pEnumerator->Release();
	pEnumerator=NULL;


	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_BaseBoard"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;              
	}

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

 	
		hr = pclsObj->Get(L"Manufacturer",0,&vtProp,0,0);
		wcscpy_s(Info.szMainBoard,MAX_PATH,vtProp.bstrVal);
		wcscat_s(Info.szMainBoard,MAX_PATH,L" ");
		hr = pclsObj->Get(L"Product", 0, &vtProp, 0, 0);  //video desc
		wcscat_s(Info.szMainBoard,MAX_PATH,vtProp.bstrVal);
		
		VariantClear(&vtProp);
		pclsObj->Release();
	}

	pEnumerator->Release();
	pEnumerator=NULL;


	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_DesktopMonitor"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;              
	}

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;
		 
		hr = pclsObj->Get(L"Description", 0, &vtProp, 0, 0);  //video desc
	    Info.vcDisplayer.push_back(vtProp.bstrVal);
		VariantClear(&vtProp);
		pclsObj->Release();
	}


	pEnumerator->Release();
	pEnumerator=NULL;


	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_SoundDevice"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;              
	}

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

		hr = pclsObj->Get(L"Description", 0, &vtProp, 0, 0);  //video desc
		wcscpy_s( Info.szSoundCard,MAX_PATH,vtProp.bstrVal);
		VariantClear(&vtProp);
		pclsObj->Release();
	}


	pEnumerator->Release();
	pEnumerator=NULL;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_PhysicalMemory"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;              
	}

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			break;
		}

		VARIANT vtProp,vtProp1,vtProp2;
		WCHAR wTmpMem[MAX_PATH];
		hr = pclsObj->Get(L"Capacity", 0, &vtProp, 0, 0);  //�ڴ��С
		
		hr = pclsObj->Get(L"Manufacturer", 0, &vtProp1, 0, 0);  //Ʒ�Ƴ���
		hr = pclsObj->Get(L"Speed", 0, &vtProp2, 0, 0);  //����

		wsprintfW(wTmpMem,L"%s %dMHZ %d MB",vtProp1.bstrVal,vtProp2.iVal,_wtoi64(vtProp.bstrVal)/1024/1024);
		Info.vcMemory.push_back(wTmpMem);
		VariantClear(&vtProp);
		pclsObj->Release();
	}


	pEnumerator->Release();
	pEnumerator=NULL;

	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM Win32_NetworkAdapterConfiguration"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;              
	}

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;
		NETCARDINFO netCardInfo;
		
		hr = pclsObj->Get(L"MACAddress", 0, &vtProp, 0, 0);  //MAC��ַ
		if(vtProp.vt==VT_EMPTY||vtProp.vt==VT_NULL||vtProp.bstrVal == NULL ||(int)vtProp.bstrVal == 0xcccccccc)
			goto inext; 
		else
			wcscpy_s(netCardInfo.szMac,vtProp.bstrVal);
			
		hr = pclsObj->Get(L"IPAddress", 0, &vtProp, 0, 0);  //�ڴ��С
		SAFEARRAY *pIn;
		pIn = vtProp.parray;
		int* buf = NULL;
	    SafeArrayAccessData(pIn, (void**)&buf);
		WCHAR * cIp = (PWCHAR)*buf; 
		if(pIn == NULL|| (int)buf == 0xcccccccc||buf == NULL)
			wcscpy_s(netCardInfo.szIp,16,L"0.0.0.0"); 		    
		else
			wcscpy_s(netCardInfo.szIp,16,cIp); 
		SafeArrayUnaccessData(pIn);
		hr = pclsObj->Get(L"Description", 0, &vtProp, 0, 0);  //Ʒ�Ƴ���
		wcscpy_s(netCardInfo.szName,vtProp.bstrVal);
		Info.vcNetCardInfos.push_back(netCardInfo);
	
		 
		 
inext:
		VariantClear(&vtProp);
		pclsObj->Release();
	}


	pEnumerator->Release();
	pEnumerator=NULL;


	pSvc->Release();
	pLoc->Release();
   CoUninitialize();

 
	hres =  CoInitialize( NULL );
	if (FAILED(hres))
	{
		return false;                
	}

	hres =  CoInitializeSecurity(
		NULL,
		-1,                         
		NULL,                       
		NULL,                       
		RPC_C_AUTHN_LEVEL_DEFAULT,  
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,                       
		EOAC_NONE,                  
		NULL                        
		);


	if (FAILED(hres))
	{
		CoUninitialize();
		return false;                  
	}

	pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator,            
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID *) &pLoc);

	if (FAILED(hres))
	{
		CoUninitialize();
		return false;                
	}

	pSvc = NULL;

	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\WMI"),
		NULL,                   
		NULL,                   
		0,                      
		NULL,                   
		0,                      
		0,                      
		&pSvc                   
		);

	if (FAILED(hres))
	{
		pLoc->Release();    
		CoUninitialize();
		return false;              
	}

	hres = CoSetProxyBlanket(
		pSvc,                       
		RPC_C_AUTHN_WINNT,          
		RPC_C_AUTHZ_NONE,           
		NULL,                       
		RPC_C_AUTHN_LEVEL_CALL,     
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,                       
		EOAC_NONE                   
		);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();    
		CoUninitialize();
		return false;              
	}

	pEnumerator = NULL;



	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t("SELECT * FROM MSStorageDriver_ATAPISmartData"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return false;              
	}
	int nTemperature = 0;
	int nTotalTime = 0;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if(0 == uReturn)
		{
			break;
		}

		VARIANT vtProp,vtProp1;


		hr = pclsObj->Get(L"VendorSpecific", 0, &vtProp, 0, 0);  //video desc
		hr = pclsObj->Get(L"InstanceName", 0, &vtProp1, 0, 0);  //video desc

		SAFEARRAY *pIn;
		pIn = vtProp.parray;
		VARTYPE vt;
		UINT dim;
		SafeArrayGetVartype(pIn,&vt);    //�����������
		dim = SafeArrayGetDim(pIn);      //���ά��
		long LBound;                           //�½�
		long UBound;                           //�Ͻ�
		SafeArrayGetLBound(pIn,1,&LBound);    //����½�
		SafeArrayGetUBound(pIn,1,&UBound);   //����Ͻ�
		BYTE *pdata = new BYTE[UBound-LBound+1];
		ZeroMemory(pdata,UBound-LBound+1);

		BYTE *buf;
		SafeArrayAccessData(pIn, (void **)&buf);
		memcpy(pdata,buf,UBound-LBound+1);
		SafeArrayUnaccessData(pIn);

		BYTE* pTemp = pdata+2;
		for(int i=2;i<UBound-LBound+1;i+=12)
		{
			pTemp = pdata+i;
			if (*pTemp == 0xc2)
			{
				//Beep(1000,200);
				nTemperature = *(pTemp+5);//Ӳ���¶�
			}

			if (*pTemp == 0x09)
			{
				//Beep(1000,200);
				nTotalTime = (*(pTemp+5)) + (*(pTemp+6)<<8);//Ӳ��ʹ��ʱ��
			}

		}
		for(UINT i = 0;i<Info.vcDiskInfo.size();i++)
		{
		   if(!_wcsnicmp(Info.vcDiskInfo[i].szName,vtProp1.bstrVal,wcslen(Info.vcDiskInfo[i].szName)))
		   {
			   WCHAR wTime[20];
			   wcscat_s(Info.vcDiskInfo[i].szInfo,MAX_PATH,L"  ʹ��ʱ�䣺");
			   _itow_s(nTotalTime,wTime,10);
			   wcscat_s(Info.vcDiskInfo[i].szInfo,MAX_PATH,wTime);
			   wcscat_s(Info.vcDiskInfo[i].szInfo,MAX_PATH,L"Сʱ");

			   wcscat_s(Info.vcDiskInfo[i].szInfo,MAX_PATH,L"  �¶ȣ�");
			   _itow_s(nTemperature,wTime,10);
			   wcscat_s(Info.vcDiskInfo[i].szInfo,MAX_PATH,wTime);
			   wcscat_s(Info.vcDiskInfo[i].szInfo,MAX_PATH,L"��");
			   break; 
		   }
		}



		VariantClear(&vtProp);
		pclsObj->Release();
	}


// 	char msg[260];
// 	//m_strTest.Format("Ӳ���Ѿ�ʹ���� %d ��Сʱ �� ���ڵ��¶��� %d C",nTotalTime,nTemperature);
// 	wsprintfA(msg,"Ӳ���Ѿ�ʹ���� %d ��Сʱ �� ���ڵ��¶��� %d C",nTotalTime,nTemperature);
// //	wcout<<nTotalTime<<"Ӳ�����ڵ��¶���"<<nTemperature<<"c";
// 	 printf("%s\r\n",msg);
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
     
    CoUninitialize();
 
    return true;
}            
void GetAdapterInfo()
{

	//PIP_ADAPTER_INFO�ṹ��ָ��洢����������Ϣ
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	//�õ��ṹ���С,����GetAdaptersInfo����
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	//����GetAdaptersInfo����,���pIpAdapterInfoָ�����;����stSize��������һ��������Ҳ��һ�������
	int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
 
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		//����������ص���ERROR_BUFFER_OVERFLOW
		//��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
		//��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������
		//�ͷ�ԭ�����ڴ�ռ�
		delete pIpAdapterInfo;
		//���������ڴ�ռ������洢����������Ϣ
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
		nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
	}
	if (ERROR_SUCCESS == nRel)
	{
		//���������Ϣ
		//�����ж�����,���ͨ��ѭ��ȥ�ж�
		while (pIpAdapterInfo)
		{ 
			cout<<"�������ƣ�"<<pIpAdapterInfo->AdapterName<<endl;
			cout<<"����������"<<pIpAdapterInfo->Description<<endl;
		 
			cout<<"����MAC��ַ��";
			for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++)
				if (i < pIpAdapterInfo->AddressLength-1)
				{
					printf("%02X-", pIpAdapterInfo->Address[i]);
				}
				else
				{
					printf("%02X\n", pIpAdapterInfo->Address[i]);
				}
				 
				//���������ж�IP,���ͨ��ѭ��ȥ�ж�
				IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
				  
				 
				cout<<"IP ��ַ��"<<pIpAddrString->IpAddress.String<<endl;
					 
				  
				pIpAdapterInfo = pIpAdapterInfo->Next;
				 
		}

	}
	//�ͷ��ڴ�ռ�
	if (pIpAdapterInfo)
	{
		delete [] pIpAdapterInfo;

		pIpAdapterInfo=NULL;
	}

}
wchar_t* GB2312ToUnicode(const char* szGBString)  
{  
	UINT nCodePage = 936; //GB2312  

	int nLength= ::MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED,szGBString,-1,NULL,1); 
	wchar_t* pBuffer = new wchar_t[nLength+1];  

	MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED,szGBString,-1,pBuffer,nLength);  

	pBuffer[nLength]=0;  

	return pBuffer;  
}  
void Convert(const char* strIn,wchar_t* strOut, int sourceCodepage, int targetCodepage)  
{  
//int len=lstrlenA(strIn);  
//int unicodeLen=MultiByteToWideChar(sourceCodepage,0,strIn,-1,NULL,0);  
// 	wchar_t* pUnicode;  
// 	pUnicode=new wchar_t[unicodeLen+1];  
// 	memset(pUnicode,0,(unicodeLen+1)*sizeof(wchar_t));  
	MultiByteToWideChar(sourceCodepage,0,strIn,-1,(LPWSTR)strOut,4096);  
// 	BYTE * pTargetData = NULL;  
// 	int targetLen=WideCharToMultiByte(targetCodepage,0,(LPWSTR)pUnicode,-1,(char *)pTargetData,0,NULL,NULL);  
// 	pTargetData=new BYTE[targetLen+1];  
// 	memset(pTargetData,0,targetLen+1);  
// 	WideCharToMultiByte(targetCodepage,0,(LPWSTR)pUnicode,-1,(char *)pTargetData,targetLen,NULL,NULL);  
// 	lstrcpyA(strOut,(char*)pTargetData);  
// 	delete pUnicode;  
// 	delete pTargetData;  
}  
void GetWaiIp(USERINFO& userInfo)
{
	HINTERNET internetopen;  
	HINTERNET internetopenurl; 
	char szTmp[10240]={0},szUrl[MAX_PATH] = "http://ip.6655.com/";
	WCHAR szTmp2[4096] = {0}  ;
	DWORD dwA;
	BOOL bOk = FALSE;

	internetopen=InternetOpenA("Testing",INTERNET_OPEN_TYPE_PRECONFIG,NULL,NULL,0); 
	if(internetopen)
	{
		internetopenurl= InternetOpenUrlA(internetopen,szUrl,NULL,0,INTERNET_FLAG_NO_CACHE_WRITE,0); 
		if(internetopenurl)
		{
			if(InternetReadFile(internetopenurl,szTmp,10240,&dwA))
			{
				/*
				IP��ַ<span id="lbl1">(�����ڵ�IP)</span>:
				</td>
				<td height="25" align="center" style="width: 271px">
				<span id="lblIP"><font color="Blue">218.249.73.27</font></span></td>
				</tr>
				<tr>
				<td width="149" height="25" align="center" style="font-size:12px;">IP����λ��:</td>
				<td height="25" align="center" style="width: 271px">��
				<span id="lblAddr"><b><font color="Red">�����е���ͨ</font></b></span>
				</td>
				</tr>
				</table>
				</div>
				*/
				Convert(szTmp,szTmp2,CP_UTF8,CP_ACP);//UTF8ת��ANSI

				//��ȡ����IP
				WCHAR * pCharTmp = wcsstr(szTmp2,L"�����ڵ�");
				pCharTmp = wcsstr(pCharTmp,L"Blue");
				pCharTmp+=6;
				int iIpLen = wcsstr(pCharTmp,L"<") - pCharTmp;

				//memcpy(pIp,pCharTmp,iIpLen*2);
				wcsncpy_s(userInfo.szWaiIp,MAX_PATH,pCharTmp,iIpLen);
				 wcscat_s(userInfo.szWaiIp,16,L" (");
				//��ȡIP���ڵ�
				pCharTmp = wcsstr(pCharTmp,L"Red");
				pCharTmp+=5;
				iIpLen = wcsstr(pCharTmp,L"<") - pCharTmp;

				//memcpy(pIpLocation,pCharTmp,iIpLen*2); 
				wcsncat_s(userInfo.szWaiIp,MAX_PATH,pCharTmp,iIpLen);
				wcscat_s(userInfo.szWaiIp,MAX_PATH,L")");
				
				bOk = TRUE;
			}
			InternetCloseHandle(internetopenurl);  
		}
		InternetCloseHandle(internetopen);  
	}
	if(!bOk)
	{
		wcscpy_s(userInfo.szWaiIp,17,L"δ֪");
		//wcscpy_s(pIpLocation,260,L"");


	}
	  
}
void  FileTimeToTimet(FILETIME ft, time_t *t )
{  
	LONGLONG ll = 0;  

	ULARGE_INTEGER ui;  
	ui.LowPart =  ft.dwLowDateTime;  
	ui.HighPart = ft.dwHighDateTime;  

	ll = (((INT64)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
	*t = (LONGLONG)(ui.QuadPart - 116444736000000000)/10000000; 


}
 
BOOL GetLocalMachineRegInfo(WCHAR * wPosi,WCHAR * wValue,LPVOID pData,DWORD iSize)
{ 
	ULONG lResult;
	HKEY hKey;
	DWORD dwSize;
	BOOL bRet = FALSE;
 

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, wPosi, 0, KEY_READ|KEY_WOW64_64KEY, &hKey);
	lResult = RegQueryValueEx(hKey, wValue, 
		NULL, NULL, NULL, &dwSize);


	if (lResult == ERROR_SUCCESS && dwSize<=iSize)
	{
		lResult = RegQueryValueEx(hKey, wValue, NULL, 
			NULL, (LPBYTE)pData, &dwSize);
		bRet = TRUE;
	}
	RegCloseKey(hKey);
 
	return bRet;
}

void GetFlashVersion(WCHAR* pFlashVersion)
{
	
	WCHAR szIeFlashVer[50],szNoIeFlaVer[50],szFilePath[MAX_PATH];
	//PlayerPath

	do 
	{
		if(!GetLocalMachineRegInfo(TEXT("SOFTWARE\\Macromedia\\FlashPlayerActiveX"),L"PlayerPath",szFilePath,MAX_PATH))
		{  
			wcscpy_s(szNoIeFlaVer,50,L"δ֪");	
			break;
		}
		else
		{
			if(!PathFileExistsW(szFilePath))
			{
				if(!GetLocalMachineRegInfo(TEXT("SOFTWARE\\Macromedia\\FlashPlayerActiveX"),L"Version",szNoIeFlaVer,50))
				{  
					wcscpy_s(szNoIeFlaVer,50,L"δ֪");	
				}
				break;
			}
			else
			{
				DWORD hTmp;
				DWORD dwSize = 0;
				char * pVersionInfo = NULL;
				if(dwSize = GetFileVersionInfoSizeW(szFilePath,&hTmp))
				{
					pVersionInfo = new char[dwSize+1];
					if(GetFileVersionInfoW(szFilePath,0,dwSize,pVersionInfo))
					{
						UINT uSize = 0;
						LPVOID  pVer = NULL;
						VerQueryValueW(pVersionInfo,L"\\StringFileInfo\\040904b0\\FileVersion",&pVer,&uSize);
						wcscpy_s(szNoIeFlaVer,50,(PWCHAR)pVer);
						delete[] pVersionInfo;
						break;
					}
					else
					{
						delete[] pVersionInfo;
					}
					
				}
			    wcscpy_s(szNoIeFlaVer,50,L"δ֪");	
				 
			}
		}
		
	} while (FALSE);

	if(!GetLocalMachineRegInfo(TEXT("SOFTWARE\\Macromedia\\FlashPlayerPlugin"),L"Version",szIeFlashVer,50))
	{ 
		wcscpy_s(szIeFlashVer,50,L"δ֪");	
	} 
	wcscpy_s(pFlashVersion,MAX_PATH,szIeFlashVer);
	wcscat_s(pFlashVersion,MAX_PATH,L"(IE)");
	wcscat_s(pFlashVersion,MAX_PATH,L"     ");
	wcscat_s(pFlashVersion,MAX_PATH,szNoIeFlaVer);
	wcscat_s(pFlashVersion,MAX_PATH,L"(��IE)");
	
}
BOOL GetIEVersion(WCHAR* pIeVersion)
{ 
	if(GetLocalMachineRegInfo(TEXT("SOFTWARE\\Microsoft\\Internet Explorer"),L"svcVersion",pIeVersion,50))
	{ 
		return TRUE;
	}
	else
	{
		wcscpy_s(pIeVersion,100,L"δ֪");	
		return FALSE;
	}
	
}
tm GetLastShutdownTime()
{ 
	tm tmShutdownTime;
	time_t ShutdownTime = 0;
	FILETIME FileTime;
	ZeroMemory(&tmShutdownTime,sizeof(tm));
	  
	if(GetLocalMachineRegInfo(TEXT("SYSTEM\\CurrentControlSet\\Control\\Windows"),L"ShutdownTime",&FileTime,sizeof(FileTime)))
	{
		//SYSTEMTIME SystemTime;
		//FileTimeToSystemTime(&FileTime, &SystemTime);
		FileTimeToTimet(FileTime, &ShutdownTime); 
		localtime_s(&tmShutdownTime, &ShutdownTime);
		////tm�ṹ�е�year�Ǵ�1900�����𣬹�Ӧ����+1900
		////tm�е�month��0~11����Ӧ����1
		//printf("ShutdownTime:%4d-%02d-%02d %02d:%02d:%02d\n", 
		//    tmShutdownTime.tm_year+1900, tmShutdownTime.tm_mon+1,
		//    tmShutdownTime.tm_mday, tmShutdownTime.tm_hour,
		//    tmShutdownTime.tm_min, tmShutdownTime.tm_sec);
		tmShutdownTime.tm_year+=1900;
		tmShutdownTime.tm_mon+=1;
	}
	return tmShutdownTime;
}
LONGLONG   OptimizeMemory() // �Ż��ڴ� ����MB
{
	PROCESSENTRY32 pentry = {sizeof(pentry)};              //����С
	HANDLE hPSnap =::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); //��������
	BOOL bMore = ::Process32First(hPSnap,&pentry);     //�õ��׸�����
	MEMORYSTATUSEX statex;

	__int64 ass ;
	statex.dwLength = sizeof (statex);


	GlobalMemoryStatusEx (&statex); 
	ass = statex.ullAvailPhys; 
	int i = 0;
	//ѭ������
	while(bMore)
	{



		// OpenProcess������ľ��
		//����MSDN��SetProcessWorkingSetSize�����������̱�����PROCESS_SET_QUOTAȨ��
		HANDLE hProcess = ::OpenProcess(PROCESS_SET_QUOTA,
			FALSE,
			pentry.th32ProcessID);
		//hProcess��Ϊ�վͱ�������˾��ֵ
		if(hProcess != NULL)
		{
			//����SetProcessWorkingSetSize����
			if(::SetProcessWorkingSetSize(hProcess, -1, -1))
				i++;
		}

		bMore = ::Process32Next(hPSnap,&pentry); //�����һ������
	}
	Sleep(1000);
	GlobalMemoryStatusEx (&statex);

	ass  =statex.ullAvailPhys - ass;
	ass/=1024*1024;

 
	::CloseHandle(hPSnap);   //�رվ��
	return ass;
}
USERINFO g_uInfo;
void   GetLocalMachineInfo(USERINFO ** uinfo)
{
	ZeroMemory(&g_uInfo,sizeof(g_uInfo));
	GetWaiIp( g_uInfo);//����IP 
	tm tt = GetLastShutdownTime();//�ϴιػ�ʱ��
	wsprintfW(g_uInfo.szShutDownTime,L"%d��%d��%d�� %d:%d:%d",tt.tm_year,tt.tm_mon,tt.tm_mday,tt.tm_hour,tt.tm_min,tt.tm_sec);

	GetIEVersion(g_uInfo.szIEVersion);//IE�汾

	GetFlashVersion(g_uInfo.szFlashVersion);//FLASH�汾

	GetUserInfo(g_uInfo);//����Ӳ����Ϣ
	*uinfo = &g_uInfo;
}