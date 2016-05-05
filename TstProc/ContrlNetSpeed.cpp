#include "StdAfx.h"
#include "ContrlNetSpeed.h"


CContrlNetSpeed::CContrlNetSpeed(void)
{
}


CContrlNetSpeed::~CContrlNetSpeed(void)
{
}

BOOL CContrlNetSpeed::Initalize()
{
	//打开设备
	m_hDevice = CreateFileA("////.//LinkDog",GENERIC_ALL,FILE_SHARE_READ,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	if(m_hDevice)
		return TRUE;
	return FALSE;

	
}

BOOL CContrlNetSpeed::LimitProcessNet(ULONG pid,BYTE bIsLimit,__int64 i64speed/*=0*/)
{
	R3R0Comm rTalk; 
	BOOL bRet;

	rTalk.PID = pid;           //进程ID
	rTalk.i64Speed = i64speed; //限制的速度（0的话则禁止访问网络）
	rTalk.bLimit = bIsLimit;   //是否限制（0的话解除限制）
	//与设备通信
	bRet = DeviceIoControl(m_hDevice,0,0,0,0,0,0,0);
	return bRet;
}
