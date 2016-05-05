#ifndef IMPLST
#define IMPLST

#include <list>
#include <vector>
#include <map>
#include <stdlib.h>
#include <Windows.h>
#pragma warning(disable:4018)
using namespace std;
 

/*系统信息*/ 
typedef struct _NetCardInfo
{
	WCHAR szName[MAX_PATH]; //网卡名称
	WCHAR szMac[18];        //MAC地址
	WCHAR szIp[16];         //IP地址	

}NETCARDINFO,*PNETCARDINFO;
typedef struct _DiskInfo
{
	WCHAR szName[MAX_PATH]; //界面不需理会
	WCHAR szInfo[MAX_PATH]; //硬盘信息	 

}DISKINFO,*PDISKINFO;

typedef struct _UserInfo
{
	WCHAR szModel[MAX_PATH];			   //电脑型号  
	WCHAR szOperatingSystem[MAX_PATH];     //操作系统  
	WCHAR szMainBoard[MAX_PATH];		   //主板      
	vector<wstring> vcDisplayer;           //显示器    
	WCHAR szCpu[MAX_PATH];                 //处理器CPU 

	vector<wstring> vcMemory;              //内存      
	vector<DISKINFO> vcDiskInfo;           //硬盘      
	vector<wstring> vcDisplayCard;         //显卡      
	WCHAR szSoundCard[MAX_PATH];           //声卡      
	vector<NETCARDINFO> vcNetCardInfos;    //网卡      
	WCHAR szWaiIp[MAX_PATH];               //外网IP    
	WCHAR szIEVersion[100];                //IE版本    
	WCHAR szFlashVersion[MAX_PATH];        //FLASH版本 
	WCHAR szBootTime[MAX_PATH];            //开机时间  
	WCHAR szShutDownTime[MAX_PATH];        //上次关机时间  
	WCHAR szSystemInstallTime[MAX_PATH];   //系统安装日期 

}USERINFO,*PUSERINFO;

/************************************************************************/
/*                  端口监控                                            */
/************************************************************************/
enum NETTYPE
{
	NET_TCP,
	NET_UDP
};
//tcp
typedef struct _TCPCONDATA 
{
	NETTYPE     enNetType;

	HICON       hicoPro;                    //进程图标
	WCHAR       szProcUserName[MAX_PATH];	//进程所属用户名

	WCHAR       szLocalAddr[MAX_PATH];    
	WCHAR       szRemoteAddr[MAX_PATH];    
	USHORT      usLocalPort;    
	USHORT      usRemotePort;    
	WCHAR       szState[MAX_PATH]; 
	WCHAR       szProName[MAX_PATH];
	WCHAR       szFullPath[MAX_PATH];
	DWORD       dwPid;

	BYTE        bBl;
	BYTE        bInsert;
	_TCPCONDATA()
	{
		bBl = 0;
		bInsert = 0;
		ZeroMemory(szFullPath, MAX_PATH);
	}
}TCPCONDATA,*PTCPCONDATA;
//udp
typedef struct _UDPCONDATA
{
	NETTYPE    enNetType;
	HICON       hicoPro;                    //进程图标
	WCHAR       szProcUserName[MAX_PATH];	//进程所属用户名 
	WCHAR        szLocalAddr[MAX_PATH];  
	USHORT       usLocalPort;  
	WCHAR       szProName[MAX_PATH];
	WCHAR       szFullPath[MAX_PATH];
	DWORD        dwPid;
	BYTE        bBl;
	BYTE        bInsert;
	_UDPCONDATA()
	{
		bBl = 0;
		bInsert = 0;
		ZeroMemory(szFullPath, MAX_PATH);
	}
}UDPCONDATA,*PUDPCONDATA;

typedef vector<TCPCONDATA> TCPVECTOR, *PTCPVECTOR;
typedef vector<UDPCONDATA> UDPVECTOR, *PUDPVECTOR;
 

typedef map<USHORT, TCPCONDATA> TCPMAP, *PTCPMAP;
typedef map<USHORT, UDPCONDATA> UDPMAP, *PUDPMAP;

typedef struct _PortInfo
{
BYTE bState;
BYTE bHl;
_PortInfo()
{
bState = 0;
bHl = 0;
}
}PORTINFO,*PPORTINFO; 
typedef map<DWORD,PORTINFO> PORTMAP,*PPORTMAP;
/************************************************************************/
/* 列表框外带数据                                                       */
/************************************************************************/

typedef struct _listdata
{
	int iImageId;
	DWORD_PTR pdata;
}LISTDATA, *PLISTDATA;

/************************************************************************/
/* 进程列表                                                             */
/************************************************************************/

typedef struct _ProcInfo
{
	ULONG		pid;
	HICON       hicoPro;                    //进程图标
	HANDLE      hpro;                       //暂时不用
	WCHAR       szProName[MAX_PATH];		//进程名
	WCHAR       szFullPath[MAX_PATH];		//全路径
	WCHAR       szProExplain[MAX_PATH];		//文件说明
	WCHAR       szProcUserName[MAX_PATH];	//进程所属用户名
	UINT        uiCpu;						//cpu占用率
	__int64     iMemUsage;					//内存用量 字节
	__int64     iDiskWrite;                 //磁盘写速度 字节/秒
	__int64     iDiskRead;                  //磁盘读速度 字节/秒
	__int64     iUpFlowCount;               //上传流量 字节
	__int64     iDownFlowCount;             //下载流量 字节

	__int64     iNetUpSpeed;                //上传速度 字节/S
	__int64     iNetDownSpeed;              //下载速度 字节/S


	__int64		last_system_time_;
	__int64   	last_time_;
	__int64		idiskreadcount;
	__int64   	idiskwritecount;
	BYTE        bBl;
	BYTE        bInsert;
	_ProcInfo()
	{
		ZeroMemory(szProExplain, MAX_PATH);
		ZeroMemory(szProName,MAX_PATH);
		ZeroMemory(szFullPath,MAX_PATH);
		bBl = 0;
		pid = 0;
		bInsert = 0;
		hicoPro = 0;
		hpro = NULL;
		iMemUsage = 0;
		uiCpu = 0;
		last_system_time_ = 0;
		last_time_ = 0;
		iDiskWrite = 0;
		iDiskRead = 0;
		iNetDownSpeed=iNetUpSpeed=iDownFlowCount=iUpFlowCount=idiskreadcount = idiskwritecount = 0;
	}


}ProcInfo,*PProcInfo;

typedef list<ProcInfo> PROCINFOLIST, *PPROCINFOLIST;

typedef map<DWORD,ProcInfo> PROCINFOMAP, *PPROCINFOMAP;
 
/************************************************************************/
/* 进程流量信息                                                         */
/************************************************************************/
/*与驱动通信的，界面不要用*/
/*获取进程流量信息*/
typedef struct user_mode_flow
{
	ULONG uPid;
	
	int bForbidNet;          // 0 为允许联网 ，1为禁止联网

	int bLimitUp;            //是否限制上传 0 不限制，1限制
	int bLimitDown;          //是否限制下载 0 不限制，1限制   

	LONGLONG upCount;        //上传流量
	LONGLONG downCount;      //下载流量

	LONG limitUpValue;       //限制的上传速度的值 KB/S   
	LONG limitDownValue;	  //限制的下载速度的值 KB/S    

}user_mode_flow,*puser_mode_flow;


/*界面用下边的结构*/
typedef struct PRO_FLOW_INFO
{
	ULONG uPid;

	int bForbidNet;          // 0 为允许联网 ，1为禁止联网

	int bLimitUp;            //是否限制上传 0 不限制，1限制
	int bLimitDown;          //是否限制下载 0 不限制，1限制   

	LONGLONG upCount;        //上传流量
	LONGLONG downCount;      //下载流量

	LONGLONG upSpeed;
	LONGLONG downSpeed;

	ULONG limitUpValue;       //限制的上传速度的值 KB/S   
	ULONG limitDownValue;	  //限制的下载速度的值 KB/S    

	BYTE bHl;

	PRO_FLOW_INFO()
	{ 
		upCount = 0;
		downCount = 0; 
	}
}PRO_FLOW_INFO,*PPRO_FLOW_INFO;


typedef map<ULONG,PRO_FLOW_INFO> PROCFLOWINFOMAP,*PPROCFLOWINFOMAP;

#endif