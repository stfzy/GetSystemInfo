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
	//���豸
	m_hDevice = CreateFileA("////.//LinkDog",GENERIC_ALL,FILE_SHARE_READ,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	if(m_hDevice)
		return TRUE;
	return FALSE;

	
}

BOOL CContrlNetSpeed::LimitProcessNet(ULONG pid,BYTE bIsLimit,__int64 i64speed/*=0*/)
{
	R3R0Comm rTalk; 
	BOOL bRet;

	rTalk.PID = pid;           //����ID
	rTalk.i64Speed = i64speed; //���Ƶ��ٶȣ�0�Ļ����ֹ�������磩
	rTalk.bLimit = bIsLimit;   //�Ƿ����ƣ�0�Ļ�������ƣ�
	//���豸ͨ��
	bRet = DeviceIoControl(m_hDevice,0,0,0,0,0,0,0);
	return bRet;
}
