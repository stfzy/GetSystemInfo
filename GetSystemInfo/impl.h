#ifndef IMPLST
#define IMPLST

#include <list>
#include <vector>
#include <map>
#include <stdlib.h>
#include <Windows.h>
#pragma warning(disable:4018)
using namespace std;
 

/*ϵͳ��Ϣ*/ 
typedef struct _NetCardInfo
{
	WCHAR szName[MAX_PATH]; //��������
	WCHAR szMac[18];        //MAC��ַ
	WCHAR szIp[16];         //IP��ַ	

}NETCARDINFO,*PNETCARDINFO;
typedef struct _DiskInfo
{
	WCHAR szName[MAX_PATH]; //���治�����
	WCHAR szInfo[MAX_PATH]; //Ӳ����Ϣ	 

}DISKINFO,*PDISKINFO;

typedef struct _UserInfo
{
	WCHAR szModel[MAX_PATH];			   //�����ͺ�  
	WCHAR szOperatingSystem[MAX_PATH];     //����ϵͳ  
	WCHAR szMainBoard[MAX_PATH];		   //����      
	vector<wstring> vcDisplayer;           //��ʾ��    
	WCHAR szCpu[MAX_PATH];                 //������CPU 

	vector<wstring> vcMemory;              //�ڴ�      
	vector<DISKINFO> vcDiskInfo;           //Ӳ��      
	vector<wstring> vcDisplayCard;         //�Կ�      
	WCHAR szSoundCard[MAX_PATH];           //����      
	vector<NETCARDINFO> vcNetCardInfos;    //����      
	WCHAR szWaiIp[MAX_PATH];               //����IP    
	WCHAR szIEVersion[100];                //IE�汾    
	WCHAR szFlashVersion[MAX_PATH];        //FLASH�汾 
	WCHAR szBootTime[MAX_PATH];            //����ʱ��  
	WCHAR szShutDownTime[MAX_PATH];        //�ϴιػ�ʱ��  
	WCHAR szSystemInstallTime[MAX_PATH];   //ϵͳ��װ���� 

}USERINFO,*PUSERINFO;

/************************************************************************/
/*                  �˿ڼ��                                            */
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

	HICON       hicoPro;                    //����ͼ��
	WCHAR       szProcUserName[MAX_PATH];	//���������û���

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
	HICON       hicoPro;                    //����ͼ��
	WCHAR       szProcUserName[MAX_PATH];	//���������û��� 
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
/* �б���������                                                       */
/************************************************************************/

typedef struct _listdata
{
	int iImageId;
	DWORD_PTR pdata;
}LISTDATA, *PLISTDATA;

/************************************************************************/
/* �����б�                                                             */
/************************************************************************/

typedef struct _ProcInfo
{
	ULONG		pid;
	HICON       hicoPro;                    //����ͼ��
	HANDLE      hpro;                       //��ʱ����
	WCHAR       szProName[MAX_PATH];		//������
	WCHAR       szFullPath[MAX_PATH];		//ȫ·��
	WCHAR       szProExplain[MAX_PATH];		//�ļ�˵��
	WCHAR       szProcUserName[MAX_PATH];	//���������û���
	UINT        uiCpu;						//cpuռ����
	__int64     iMemUsage;					//�ڴ����� �ֽ�
	__int64     iDiskWrite;                 //����д�ٶ� �ֽ�/��
	__int64     iDiskRead;                  //���̶��ٶ� �ֽ�/��
	__int64     iUpFlowCount;               //�ϴ����� �ֽ�
	__int64     iDownFlowCount;             //�������� �ֽ�

	__int64     iNetUpSpeed;                //�ϴ��ٶ� �ֽ�/S
	__int64     iNetDownSpeed;              //�����ٶ� �ֽ�/S


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
/* ����������Ϣ                                                         */
/************************************************************************/
/*������ͨ�ŵģ����治Ҫ��*/
/*��ȡ����������Ϣ*/
typedef struct user_mode_flow
{
	ULONG uPid;
	
	int bForbidNet;          // 0 Ϊ�������� ��1Ϊ��ֹ����

	int bLimitUp;            //�Ƿ������ϴ� 0 �����ƣ�1����
	int bLimitDown;          //�Ƿ��������� 0 �����ƣ�1����   

	LONGLONG upCount;        //�ϴ�����
	LONGLONG downCount;      //��������

	LONG limitUpValue;       //���Ƶ��ϴ��ٶȵ�ֵ KB/S   
	LONG limitDownValue;	  //���Ƶ������ٶȵ�ֵ KB/S    

}user_mode_flow,*puser_mode_flow;


/*�������±ߵĽṹ*/
typedef struct PRO_FLOW_INFO
{
	ULONG uPid;

	int bForbidNet;          // 0 Ϊ�������� ��1Ϊ��ֹ����

	int bLimitUp;            //�Ƿ������ϴ� 0 �����ƣ�1����
	int bLimitDown;          //�Ƿ��������� 0 �����ƣ�1����   

	LONGLONG upCount;        //�ϴ�����
	LONGLONG downCount;      //��������

	LONGLONG upSpeed;
	LONGLONG downSpeed;

	ULONG limitUpValue;       //���Ƶ��ϴ��ٶȵ�ֵ KB/S   
	ULONG limitDownValue;	  //���Ƶ������ٶȵ�ֵ KB/S    

	BYTE bHl;

	PRO_FLOW_INFO()
	{ 
		upCount = 0;
		downCount = 0; 
	}
}PRO_FLOW_INFO,*PPRO_FLOW_INFO;


typedef map<ULONG,PRO_FLOW_INFO> PROCFLOWINFOMAP,*PPROCFLOWINFOMAP;

#endif