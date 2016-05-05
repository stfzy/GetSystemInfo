#include "impl.h"

#ifdef GETPROCINFO
#define DLLEXIMPORT __declspec(dllexport)
#else
#define DLLEXIMPORT __declspec(dllimport)
#endif

extern "C" void DLLEXIMPORT __stdcall GetProcInfos(PPROCINFOMAP * pProInfoList);

extern "C" void DLLEXIMPORT __stdcall GetUdpTcp(PTCPVECTOR * tcpvector,PUDPVECTOR * udpvector);

extern "C" DWORD DLLEXIMPORT __stdcall CloseProcess(DWORD dwPid);
 
extern "C" void DLLEXIMPORT __stdcall JmpToFilePath(WCHAR * filepath);

extern "C" void DLLEXIMPORT __stdcall LookAtFileProperties(WCHAR * filepath);

/* ��ȡ��������������Ϣ */
extern "C" BOOL DLLEXIMPORT __stdcall GetProcFlowsInfos(PPROCFLOWINFOMAP * ppprocflowmap);

//************************************
// Method:    LimitProcNet
  
// Returns:    BOOL  
// Qualifier:  ���ƽ�������
// Parameter: ULONG pid    ���������ٵĽ��̵�pid
// Parameter: BOOL bLimit  TRUE ��ֹ������FALSE �����������������ΪTRUE �����±���������������д
// Parameter: ULONG ulLimiDown ���Ƶ������ٶ� KB/S  ����д -1���ʾ���Դ˲��� ���ָ����� ��д 0������0����Ϊ���Ƶ���
// Parameter: ULONG ulLimitUp  ���Ƶ��ϴ��ٶ� KB/S  ����д -1���ʾ���Դ˲��� ���ָ����� ��д 0������0����Ϊ���Ƶ���
//************************************
extern "C" BOOL DLLEXIMPORT __stdcall LimitProcNet(ULONG pid,BOOL bLimit,LONG ulLimiDown = -1,LONG ulLimitUp = -1);
extern "C" BOOL DLLEXIMPORT __stdcall EnableProDebugPrivilege();

extern "C" BOOL DLLEXIMPORT __stdcall ClearProcFlows();

extern "C" void DLLEXIMPORT __stdcall  GetLocalMachineInfos(PUSERINFO * uinfo); //��ȡ���������Ϣ���Լ������ڴ棬��ʹ��һ��ȫ�ֱ�����
extern "C" void DLLEXIMPORT __stdcall  GetSysRuntime(WCHAR * pTime);           //��ȡϵͳ����ʱ�䣬�Լ������ڴ棬����ָ�롣�� WCHAR szTime[260]; ��һ��100����
extern "C" LONGLONG DLLEXIMPORT __stdcall  OptimizeMem();                      //�Ż��ڴ棬�����Ż����ڴ��С����λΪMB