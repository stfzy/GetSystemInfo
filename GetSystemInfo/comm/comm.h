#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>
#include <ShellAPI.h>
 #include <malloc.h>
#include "../impl.h"
#pragma comment(lib, "version.lib")
#pragma comment(lib,"psapi.lib")


 DWORD  GetProcessUseMemory(DWORD dwProcID);//��ȡ�ڴ�˽�м�
BOOL IsVistaAndLater();          //�ж�ϵͳ�汾�ǲ���vista ���Ժ�

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath);
void DebugPrivilege();
void DebugPrivilege2();
//��ȡ��������·��
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH]);
//��ȡ�ļ�����
void GetFileDescription(TCHAR* filepath,WCHAR* pfiledesc);
bool AdjustPrivileges() ;
/// ���CPU�ĺ���
int get_processor_number();
BOOL EnableDebugPrivilege();
/// ʱ��ת��
LONGLONG file_time_2_utc(const FILETIME* ftime);
 HICON GetFileIcon(LPCTSTR lpFileName);

//��ȡ�����û���
BOOL GetProcessUserName(DWORD dwID, LPWSTR szUserName);
 
BOOL GetProcName(DWORD pid,LPWSTR szProName);

void LookFileProperties(TCHAR* filepath);
 
void FindFile(TCHAR* filepath);
int GetProcMemFromPerformence(WCHAR* pProcName,DWORD dwProId);
LONGLONG   OptimizeMemory();
void   GetLocalMachineInfo(USERINFO ** uinfo);
 void   GetSystemRuntime(WCHAR * pTime);