#include "stdafx.h"
#include "GetTcpUdpState.h"
#include "..\comm\comm.h"
 
#include <Shlwapi.h>
#include <winsock.h>
#include <iphlpapi.h>

#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"shlwapi.lib")

CGetTcpUdpState * CGetTcpUdpState::m_instance = 0;



CGetTcpUdpState::CGetTcpUdpState(void):m_pTcpTable(NULL),m_pUdpTable(NULL)
{	 
}

// CGetTcpUdpState::~CGetTcpUdpState(void)
// {
// 	if(m_pUdpTable)
// 		free(m_pUdpTable);
// 	if(m_pTcpTable)
// 		free(m_pTcpTable);
// }

void CGetTcpUdpState::_AnalyticalTcpData(PTCPVECTOR tcpvector, BYTE* pHave)
{ 
	static BYTE bHave = 0;
	for(int i = 0;i<m_pTcpTable->dwNumEntries ; i++)
	{ 
		TCPCONDATA tcpConData;
		IN_ADDR     localAddr;    
		IN_ADDR     remoteAddr;    
 
		localAddr.S_un.S_addr = m_pTcpTable->table[i].dwLocalAddr;    
		remoteAddr.S_un.S_addr = m_pTcpTable->table[i].dwRemoteAddr;    
		MultiByteToWideChar(CP_ACP, 0, inet_ntoa(localAddr), -1, tcpConData.szLocalAddr, MAX_PATH);    
		MultiByteToWideChar(CP_ACP, 0, inet_ntoa(remoteAddr), -1, tcpConData.szRemoteAddr, MAX_PATH);    
		switch (m_pTcpTable->table[i].dwState)    
		{    
		case MIB_TCP_STATE_CLOSED:    
			wsprintf(tcpConData.szState, _T("%s"), _T("关闭连接"));    // 关闭连接
			break;    
		case MIB_TCP_STATE_LISTEN:    
			wsprintf(tcpConData.szState, _T("%s"), _T("监听")); //监听
			break;    
		case MIB_TCP_STATE_SYN_SENT:    
			wsprintf(tcpConData.szState, _T("%s"), _T("同步发送"));  //同步发送
			break;    
		case MIB_TCP_STATE_SYN_RCVD:    
			wsprintf(tcpConData.szState, _T("%s"), _T("同步接收"));    //同步接收
			break;    
		case MIB_TCP_STATE_ESTAB:    
			wsprintf(tcpConData.szState, _T("%s"), _T("已连接"));   //建立连接
			break;    
		case MIB_TCP_STATE_FIN_WAIT1:    
			wsprintf(tcpConData.szState, _T("%s"), _T("等待ACK"));    //等待ACK
			break;    
		case MIB_TCP_STATE_FIN_WAIT2:    
			wsprintf(tcpConData.szState, _T("%s"), _T("等待FIN"));    //等待FIN
			break;    
		case MIB_TCP_STATE_CLOSE_WAIT:    
			wsprintf(tcpConData.szState, _T("%s"), _T("等待关闭"));    //等待关闭
			break;    
		case MIB_TCP_STATE_CLOSING:    
			wsprintf(tcpConData.szState, _T("%s"), _T("正在关闭"));    //正在关闭
			break;    
		case MIB_TCP_STATE_LAST_ACK:    
			wsprintf(tcpConData.szState, _T("%s"), _T("最后握手"));    //最后握手
			break;    
		case MIB_TCP_STATE_TIME_WAIT:    
			wsprintf(tcpConData.szState, _T("%s"), _T("超时等待"));    //超时等待
			break;    
		case MIB_TCP_STATE_DELETE_TCB:    
			wsprintf(tcpConData.szState, _T("%s"), _T("删除TCB"));    //
			break;    
		}    
		tcpConData.usLocalPort = ntohs((USHORT) m_pTcpTable->table[i].dwLocalPort);    
		tcpConData.usRemotePort = _tcscmp(tcpConData.szState, _T("监听")) == 0 ? 0 : ntohs((USHORT) m_pTcpTable->table[i].dwRemotePort);    
		tcpConData.enNetType = NET_TCP;
		tcpConData.dwPid = m_pTcpTable->table[i].dwOwningPid;
		 
		GetProcessFullPath(tcpConData.dwPid,tcpConData.szFullPath);
	  
	    GetProcessUserName(tcpConData.dwPid, tcpConData.szProcUserName);
		  

		//if (*tcpConData.szFullPath == 0)
		//	_tcscpy_s(tcpConData.szProName, MAX_PATH, g_ProcInfoMap[tcpConData.dwPid].szProName);
		//else
		 /*
		 //HICON
		 if(m_ProInfos[pSystemProc->ProcessId].szFullPath)
		 {
		 m_ProInfos[pSystemProc->ProcessId].hicoPro = GetFileIcon(m_ProInfos[pSystemProc->ProcessId].szFullPath);
		 DeleteObject( m_ProInfos[pSystemProc->ProcessId].hicoPro );
		 }
		 else
		 m_ProInfos[pSystemProc->ProcessId].hicoPro = GetFileIcon(_T("c:\\windows\\system32\\svchost.exe"));
		 */
		if( *tcpConData.szFullPath == 0)
		{
			WCHAR szProName[260];
			GetProcName(tcpConData.dwPid,szProName);
			_tcscpy_s(tcpConData.szProName, MAX_PATH, szProName);
		 //  tcpConData.hicoPro = GetFileIcon(_T("c:\\windows\\system32\\svchost.exe"));
		}
		else
		{
			// tcpConData.hicoPro = GetFileIcon(tcpConData.szFullPath);
			_tcscpy_s(tcpConData.szProName, MAX_PATH, PathFindFileName(tcpConData.szFullPath));
		}

		tcpConData.bBl = bHave;
		//(*tcpvector)[tcpConData.usLocalPort] = tcpConData;
		tcpvector->push_back(tcpConData);
	 
/*nextloop:;*/
	}   	
	free(m_pTcpTable); 
	bHave ^= 1;
	*pHave = bHave;
	m_pTcpTable = NULL;

}

void CGetTcpUdpState::_AnalyticalUdpData(PUDPVECTOR udpvector, BYTE* pHave)
{
	 
	static BYTE bHave = 0;
	for(int i = 0;i<m_pUdpTable->dwNumEntries ; i++)
 	{  
  

		UDPCONDATA udpConData;
		IN_ADDR    localAddr;  

		localAddr.S_un.S_addr = m_pUdpTable->table[i].dwLocalAddr;  
		udpConData.usLocalPort = ntohs((USHORT) m_pUdpTable->table[i].dwLocalPort);  
		MultiByteToWideChar(CP_ACP, 0, inet_ntoa(localAddr), -1, udpConData.szLocalAddr, 1024);  
		udpConData.enNetType = NET_UDP;
		udpConData.dwPid = m_pUdpTable->table[i].dwOwningPid;
		
		GetProcessFullPath(udpConData.dwPid,udpConData.szFullPath);
	    GetProcessUserName(udpConData.dwPid, udpConData.szProcUserName);
		 
		 
		if( *udpConData.szFullPath == 0)
		{
			WCHAR szProName[260];
			GetProcName(udpConData.dwPid,szProName);
			
			_tcscpy_s(udpConData.szProName, MAX_PATH, szProName);
			// udpConData.hicoPro = GetFileIcon(_T("c:\\windows\\system32\\svchost.exe"));
		}
		else
		{
			_tcscpy_s(udpConData.szProName, MAX_PATH, PathFindFileName(udpConData.szFullPath)); 
			// udpConData.hicoPro = GetFileIcon(udpConData.szFullPath);
		}
		udpConData.bBl = bHave;
		udpvector->push_back(udpConData);
		//udpmap->push_back(udpConData);
	 
	}  
	free(m_pUdpTable); 
	bHave ^= 1;
	*pHave = bHave;
	m_pUdpTable = NULL;
}

BOOL CGetTcpUdpState::_InitalizeTcp()
{
	DWORD dwSize = 0;
	BOOL bRet = FALSE;
	do 
	{ 
		//先获取需要申请的内存大小
		DWORD dwGetRet = GetExtendedTcpTable(NULL,&dwSize,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
		if (dwGetRet == ERROR_INVALID_PARAMETER)
		{
			//获取失败直接跳出
			break;
		}
		//申请内存
		m_pTcpTable = (PMIB_TCPTABLE_OWNER_PID) malloc(dwSize);

		if(!m_pTcpTable)
			break;//申请失败跳出

		if(GetExtendedTcpTable(m_pTcpTable,&dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL , 0)!=NO_ERROR)
		{
			free(m_pTcpTable);//如果获取失败则释放之前申请的内存
			m_pTcpTable = NULL;
			break;//跳出
		}
		bRet = TRUE;
	} while (FALSE);
	return bRet;
}

BOOL CGetTcpUdpState::_InitalizeUdp()
{
	DWORD dwSize = 0;
	BOOL bRet = FALSE;
	do 
	{
		//先获取需要申请的内存大小
		if (GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INVALID_PARAMETER)
		{
			//获取失败直接跳出
			break;
		}
		//申请内存
		m_pUdpTable = (PMIB_UDPTABLE_OWNER_PID) malloc(dwSize);

		if(!m_pUdpTable)
			break;//申请失败跳出

		if(GetExtendedUdpTable(m_pUdpTable,&dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)!=NO_ERROR)
		{
			free(m_pUdpTable);//如果获取失败则释放之前申请的内存
			m_pUdpTable = NULL;
			break;//跳出
		}
		bRet = TRUE;
	} while (FALSE);
	return bRet;
}

BOOL CGetTcpUdpState::_GetTcpTable(PTCPVECTOR tcpvector)
{
	BOOL bRet = FALSE;
	 if(bRet = _InitalizeTcp())
	 { 
		 BYTE bHave;
		_AnalyticalTcpData( tcpvector, &bHave);
		 
	 }
	 return bRet;
	
}

BOOL CGetTcpUdpState::_GetUdpTable(PUDPVECTOR tudvector)
{
	BOOL bRet = FALSE;
	if(bRet = _InitalizeUdp())
	{  
		BYTE bHave;
		_AnalyticalUdpData(tudvector, &bHave);
	 
	}	
	return bRet;
}

 
BOOL CGetTcpUdpState::GetAllNetConStatus(PTCPVECTOR * tcpvector,PUDPVECTOR * udpvector)
{
	 
	 
	BOOL bRet =FALSE;
	do 
	{
 		if (!tcpvector || !udpvector)
 			break;

// 		if(!m_tcpVecotor.empty())
// 		{
// 			//vector<TCPCONDATA> TCPVECTOR, 
// 			vector<TCPCONDATA>::iterator it;
// 			it =  m_tcpVecotor.begin();
// 
// 			while (it != m_tcpVecotor.end())
// 			{ 
// 			 
// 				if ( it->hicoPro)
// 				{ 					
// 					DestroyIcon(it->hicoPro);  
// 				}
// 				it++; 
// 			    Sleep(1);
// 			}
// 		}
// 		if(!m_udpVecotor.empty())
// 		{
// 			vector<UDPCONDATA>::iterator it;
// 			it =  m_udpVecotor.begin();
// 
// 			while (it != m_udpVecotor.end())
// 			{ 
// 				 
// 				if (it->hicoPro)
// 				{ 					
// 					DestroyIcon(it->hicoPro);  
// 				}
// 				it++; 
// 				Sleep(1);
// 			 
// 			}
// 		} 
		m_tcpVecotor.clear();
		m_udpVecotor.clear();
		if ( _GetTcpTable(&m_tcpVecotor)  && _GetUdpTable(&m_udpVecotor) )
		{
			bRet = TRUE;
		}
	} while (FALSE);
	
	 *tcpvector = &m_tcpVecotor;
	 *udpvector = &m_udpVecotor;

	return bRet;
}

CGetTcpUdpState * CGetTcpUdpState::GetInstance()
{
	if(m_instance == NULL)
	{
		m_instance = new CGetTcpUdpState;
		return m_instance;
	}
	return m_instance;
}
