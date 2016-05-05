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

/* 获取进程流量网速信息 */
extern "C" BOOL DLLEXIMPORT __stdcall GetProcFlowsInfos(PPROCFLOWINFOMAP * ppprocflowmap);

//************************************
// Method:    LimitProcNet
  
// Returns:    BOOL  
// Qualifier:  控制进程网速
// Parameter: ULONG pid    被控制网速的进程的pid
// Parameter: BOOL bLimit  TRUE 禁止联网，FALSE 允许联网，如果此项为TRUE ，则下边两个参数不用填写
// Parameter: ULONG ulLimiDown 限制的下载速度 KB/S  如填写 -1则表示忽略此参数 ，恢复限制 填写 0，大于0的则为限制的数
// Parameter: ULONG ulLimitUp  限制的上传速度 KB/S  如填写 -1则表示忽略此参数 ，恢复限制 填写 0，大于0的则为限制的数
//************************************
extern "C" BOOL DLLEXIMPORT __stdcall LimitProcNet(ULONG pid,BOOL bLimit,LONG ulLimiDown = -1,LONG ulLimitUp = -1);
extern "C" BOOL DLLEXIMPORT __stdcall EnableProDebugPrivilege();

extern "C" BOOL DLLEXIMPORT __stdcall ClearProcFlows();

extern "C" void DLLEXIMPORT __stdcall  GetLocalMachineInfos(PUSERINFO * uinfo); //获取本机相关信息，自己申请内存，或使用一个全局变量。
extern "C" void DLLEXIMPORT __stdcall  GetSysRuntime(WCHAR * pTime);           //获取系统运行时间，自己申请内存，传入指针。如 WCHAR szTime[260]; ，一般100就行
extern "C" LONGLONG DLLEXIMPORT __stdcall  OptimizeMem();                      //优化内存，返回优化的内存大小，单位为MB