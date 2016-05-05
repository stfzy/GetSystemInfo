#include "StdAfx.h"
#include "GetProcFlows.h"
#include <Windows.h>
#include <winioctl.h>

#define DEVICE_SYMB "\\\\.\\JMProcFlowDeviceSym"
#define IOC_GET_PRO_COUNT  (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_ANY_ACCESS)  
#define IOC_GET_PRO_INFOS  (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x901,METHOD_BUFFERED,FILE_ANY_ACCESS)  
#define IOC_SET_PRO_INFOS  (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x902,METHOD_BUFFERED,FILE_ANY_ACCESS)  
#define IOC_SET_PRO_ZERO   (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x903,METHOD_BUFFERED,FILE_ANY_ACCESS)  
 
#define USER_STRU_SIZE (sizeof(user_mode_flow))	

CGetProcFlows* CGetProcFlows::m_sSingle = NULL;

CGetProcFlows::CGetProcFlows(void)
{
	
}

CGetProcFlows * CGetProcFlows::GetInstance()
{
	if(m_sSingle)
		return m_sSingle;
	m_sSingle = new CGetProcFlows;
	return m_sSingle;
}

BOOL CGetProcFlows::GetProcFlows(PPROCFLOWINFOMAP * proinfo)
{
	BOOL bRet;
	BYTE bHave;
	bRet = RealGetFlowInfo(proinfo,&bHave);
	if(bRet)
	{ 
		map<DWORD, PRO_FLOW_INFO>::iterator it;
		it =  m_proFlowInfo.begin();

		while (it != m_proFlowInfo.end())
		{
			PRO_FLOW_INFO * p = &(*it).second;
			if (p->bHl == bHave)
			{  
				m_proFlowInfo.erase(it++);
				continue;
			}
			it++; 
		}
	}
	return bRet;
}

BOOL CGetProcFlows::RealGetFlowInfo(PPROCFLOWINFOMAP * proinfo,BYTE* pbHave)
{
	static BYTE  bHave = 0;
	ULONG bytesReturned,proCount;  
	BOOL bRet = FALSE;
	HANDLE hDevice = CreateFileA(DEVICE_SYMB,  
		GENERIC_READ | GENERIC_WRITE,  
		0,  
		NULL,  
		CREATE_ALWAYS,  
		FILE_ATTRIBUTE_NORMAL,  
		NULL); 

	if( hDevice == INVALID_HANDLE_VALUE)
	{
		return bRet;
	}
	else
	{ 
		do 
		{ 
			bRet = DeviceIoControl(hDevice,  
				IOC_GET_PRO_COUNT,    //我们自定义的功能号
				0,                    //传入驱动的内容
				0,                    //传入内容长度
				0,                    //驱动输出的缓冲区 
				0,                    //驱动输出缓冲区大小
				&bytesReturned,       //返回的长度
				NULL);

			proCount = bytesReturned;

			if(!bRet)
				break;
			//user_mode_flow * umf =(user_mode_flow *) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,proCount*sizeof(user_mode_flow));
			user_mode_flow * umf = new user_mode_flow[proCount];
			if(umf)
			{
				bRet = DeviceIoControl(hDevice,  
					IOC_GET_PRO_INFOS, //我们自定义的功能号   
					&proCount,               //传入驱动的内容   
					4,						 //传入内容长度   
					umf,					 //驱动输出的缓冲区   
					proCount * USER_STRU_SIZE, //驱动输出缓冲区大小   
					&bytesReturned,			 //返回的长度   
					NULL);

				for(int i =0;i<proCount;i++)
				{ 

					m_proFlowInfo[umf[i].uPid].downSpeed = umf[i].downCount - m_proFlowInfo[umf[i].uPid].downCount;
					m_proFlowInfo[umf[i].uPid].upSpeed = umf[i].upCount - m_proFlowInfo[umf[i].uPid].upCount;
	             
					if(m_proFlowInfo[umf[i].uPid].downSpeed<0)
					 m_proFlowInfo[umf[i].uPid].downSpeed=0;
				 
				 
					if(m_proFlowInfo[umf[i].uPid].upSpeed<0)
					 m_proFlowInfo[umf[i].uPid].upSpeed=0;

					m_proFlowInfo[umf[i].uPid].bForbidNet = umf[i].bForbidNet;
					m_proFlowInfo[umf[i].uPid].bLimitDown= umf[i].bLimitDown;
					m_proFlowInfo[umf[i].uPid].bLimitUp= umf[i].bLimitUp;
					m_proFlowInfo[umf[i].uPid].downCount= umf[i].downCount;
					m_proFlowInfo[umf[i].uPid].limitDownValue= umf[i].limitDownValue;
					m_proFlowInfo[umf[i].uPid].limitUpValue= umf[i].limitUpValue;
					m_proFlowInfo[umf[i].uPid].upCount= umf[i].upCount;
					m_proFlowInfo[umf[i].uPid].uPid= umf[i].uPid;

					m_proFlowInfo[umf[i].uPid].bHl =  bHave;
					  
					 
					if(m_proFlowInfo[umf[i].uPid].downSpeed > m_proFlowInfo[umf[i].uPid].limitDownValue && m_proFlowInfo[umf[i].uPid].bLimitDown)
					{
						m_proFlowInfo[umf[i].uPid].downSpeed =m_proFlowInfo[umf[i].uPid].limitDownValue;

					}
					if(m_proFlowInfo[umf[i].uPid].upSpeed > m_proFlowInfo[umf[i].uPid].limitUpValue && m_proFlowInfo[umf[i].uPid].bLimitUp)
					{
						m_proFlowInfo[umf[i].uPid].upSpeed = m_proFlowInfo[umf[i].uPid].limitUpValue;
					}
				}

				delete umf;
				//HeapFree(GetProcessHeap(),HEAP_NO_SERIALIZE,umf);
			}
		} while ( FALSE ); 
		CloseHandle( hDevice );
	}
	*proinfo = &m_proFlowInfo;
	bHave ^= 1;
    *pbHave= bHave;
	return bRet;
}

BOOL CGetProcFlows::LimitProcSpeed(ULONG pid, BOOL bForbitNet,LONG limitDown /*= -1*/,LONG limitUp /*= -1*/)
{ 
	ULONG bytesReturned;  
	BOOL bRet = FALSE;
	user_mode_flow  umf;

	HANDLE hDevice = CreateFileA(DEVICE_SYMB,  
		GENERIC_READ | GENERIC_WRITE,  
		0,  
		NULL,  
		CREATE_ALWAYS,  
		FILE_ATTRIBUTE_NORMAL,  
		NULL); 

	if( hDevice == INVALID_HANDLE_VALUE)
	{
		return bRet;
	} 
	//设置要修改的进程id
	umf.uPid = pid;
	do 
	{
		//如果禁止联网的话，直接返回
		if(bForbitNet)
		{
			umf.bForbidNet = 1;
			break;
		}
		//如果限制网速的话，证明允许联网
		umf.bForbidNet = 0;
		umf.limitDownValue = limitDown * 1024;
		umf.limitUpValue = limitUp * 1024;
		 
	} while (FALSE);
	 
	bRet = DeviceIoControl(hDevice,  
		IOC_SET_PRO_INFOS,       //我们自定义的功能号   
		&umf,                //传入驱动的内容   
		sizeof(user_mode_flow),						  //传入内容长度   
		0,					  //驱动输出的缓冲区   
		0,//驱动输出缓冲区大小   
		&bytesReturned,			  //返回的长度   
		NULL);

	CloseHandle( hDevice );
	return bRet;
}

BOOL CGetProcFlows::ClearProcFlow()
{
	ULONG bytesReturned;  
	BOOL bRet = FALSE;
	 

	HANDLE hDevice = CreateFileA(DEVICE_SYMB,  
		GENERIC_READ | GENERIC_WRITE,  
		0,  
		NULL,  
		CREATE_ALWAYS,  
		FILE_ATTRIBUTE_NORMAL,  
		NULL); 

	if( hDevice == INVALID_HANDLE_VALUE)
	{
		return bRet;
	}

	bRet = DeviceIoControl(hDevice,  
		IOC_SET_PRO_ZERO,       //我们自定义的功能号   
		0,                //传入驱动的内容   
		0,						  //传入内容长度   
		0,					  //驱动输出的缓冲区   
		0,                    //驱动输出缓冲区大小   
		&bytesReturned,			  //返回的长度   
		NULL);

	CloseHandle( hDevice );
	return bRet;
}

 