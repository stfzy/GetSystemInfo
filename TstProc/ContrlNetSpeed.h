#pragma once
#include <Windows.h>
struct R3R0Comm
{
	ULONG PID;
	BYTE bLimit;
	__int64 i64Speed;
};
/*************************************/
/********进程上传和下载的流量*********/
/*************************************/
struct ProcessFlow
{
	ULONG PID;
	__int64 iUpFlow;
	__int64 iDownFlow;
};
class CContrlNetSpeed
{
public:
	CContrlNetSpeed(void);
	~CContrlNetSpeed(void);
	BOOL Initalize();
	BOOL LimitProcessNet(ULONG pid,BYTE bIsLimit,__int64 i64speed=0);
private:
	HANDLE m_hDevice;
};

