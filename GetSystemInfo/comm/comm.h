#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>
#include <ShellAPI.h>
 #include <malloc.h>
#include "../impl.h"
#pragma comment(lib, "version.lib")
#pragma comment(lib,"psapi.lib")


 DWORD  GetProcessUseMemory(DWORD dwProcID);//获取内存私有集
BOOL IsVistaAndLater();          //判断系统版本是不是vista 及以后

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath);
void DebugPrivilege();
void DebugPrivilege2();
//获取进程完整路径
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH]);
//获取文件描述
void GetFileDescription(TCHAR* filepath,WCHAR* pfiledesc);
bool AdjustPrivileges() ;
/// 获得CPU的核数
int get_processor_number();
BOOL EnableDebugPrivilege();
/// 时间转换
LONGLONG file_time_2_utc(const FILETIME* ftime);
 HICON GetFileIcon(LPCTSTR lpFileName);

//获取进程用户名
BOOL GetProcessUserName(DWORD dwID, LPWSTR szUserName);
 
BOOL GetProcName(DWORD pid,LPWSTR szProName);

void LookFileProperties(TCHAR* filepath);
 
void FindFile(TCHAR* filepath);
int GetProcMemFromPerformence(WCHAR* pProcName,DWORD dwProId);
LONGLONG   OptimizeMemory();
void   GetLocalMachineInfo(USERINFO ** uinfo);
 void   GetSystemRuntime(WCHAR * pTime);