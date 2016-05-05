 /*!
  * 文件名： GetProcList.h
  * 创建日期：2015/12/30 14:04
  *
  * 作者：沈童
  * 邮箱：shentong@jiangmin.com
  *
  * 摘要：获取进程列表及相关信息（内存、cpu使用，读写磁盘速率，文件说明）
  *
  *  
  *
  * 备注：
 */
#pragma once
#include "..\impl.h"
#include "..\comm\comm.h"

typedef enum _THREAD_STATE
{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
}THREAD_STATE;

typedef enum _KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVertualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel
}KWAIT_REASON;
typedef LONG KPRIORITY;

typedef LONG NTSTATUS;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID,*PCLIENT_ID;

typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER KernelTime;               //CPU内核模式使用时间；
	LARGE_INTEGER UserTime;                 //CPU用户模式使用时间；
	LARGE_INTEGER CreateTime;               //线程创建时间；
	ULONG         WaitTime;                 //等待时间；
	PVOID         StartAddress;             //线程开始的虚拟地址；
	CLIENT_ID     ClientId;                 //线程标识符；
	KPRIORITY     Priority;                 //线程优先级；
	KPRIORITY     BasePriority;             //基本优先级；
	ULONG         ContextSwitchCount;       //环境切换数目；
	THREAD_STATE  State;                    //当前状态；
	KWAIT_REASON  WaitReason;               //等待原因；
}SYSTEM_THREADS, *PSYSTEM_THREADS;



typedef struct _IO_COUNTERS1
{
	LARGE_INTEGER ReadOperationCount;       //I/O读操作数目；
	LARGE_INTEGER WriteOperationCount;      //I/O写操作数目；
	LARGE_INTEGER OtherOperationCount;      //I/O其他操作数目；
	LARGE_INTEGER ReadTransferCount;        //I/O读数据数目；
	LARGE_INTEGER WriteTransferCount;       //I/O写数据数目；
	LARGE_INTEGER OtherTransferCount;       //I/O其他操作数据数目；
}IO_COUNTERS1, *PIO_COUNTERS1;
typedef struct _LSA_UNICODE_STRING
{
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR   Buffer;
}LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef LSA_UNICODE_STRING UNICODE_STRING, *PUNICODE_STRING;



typedef struct _VM_COUNTERS
{
	SIZE_T PeakVirtualSize;                  //虚拟存储峰值大小；
	SIZE_T VirtualSize;                      //虚拟存储大小；
	SIZE_T PageFaultCount;                   //页故障数目；
	SIZE_T PeakWorkingSetSize;               //工作集峰值大小；
	SIZE_T WorkingSetSize;                   //工作集大小；
	SIZE_T QuotaPeakPagedPoolUsage;          //分页池使用配额峰值；
	SIZE_T QuotaPagedPoolUsage;              //分页池使用配额；
	SIZE_T QuotaPeakNonPagedPoolUsage;       //非分页池使用配额峰值；
	SIZE_T QuotaNonPagedPoolUsage;           //非分页池使用配额；
	SIZE_T PagefileUsage;                    //页文件使用情况；
	SIZE_T PeakPagefileUsage;                //页文件使用峰值；
}VM_COUNTERS, *PVM_COUNTERS;
typedef struct _SYSTEM_PROCESSES
{
	ULONG          NextEntryDelta;          //构成结构序列的偏移量；
	ULONG          ThreadCount;             //线程数目；
	ULONG          Reserved1[6];
	LARGE_INTEGER  CreateTime;              //创建时间；
	LARGE_INTEGER  UserTime;                //用户模式(Ring 3)的CPU时间；
	LARGE_INTEGER  KernelTime;              //内核模式(Ring 0)的CPU时间；
	UNICODE_STRING ProcessName;             //进程名称；
	KPRIORITY      BasePriority;            //进程优先权；
	ULONG          ProcessId;               //进程标识符；
	ULONG          InheritedFromProcessId;  //父进程的标识符；
	ULONG          HandleCount;             //句柄数目；
	ULONG          Reserved2[2];
	VM_COUNTERS    VmCounters;              //虚拟存储器的结构，见下；
	IO_COUNTERS1    IoCounters;              //IO计数结构，见下；
	SYSTEM_THREADS Threads[1];              //进程相关线程的结构数组，见下；
}SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;
typedef DWORD    SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(__stdcall *NTQUERYSYSTEMINFORMATION)
(IN     SYSTEM_INFORMATION_CLASS,
IN OUT PVOID,
IN     ULONG,
OUT    PULONG OPTIONAL);

#define NT_PROCESSTHREAD_INFO        0x05
#define MAX_INFO_BUF_LEN             0x500000
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)
class CGetProcList
{
public:
	CGetProcList(void);
	~CGetProcList(void);
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
	int m_processor_count_;
	BOOL GetProcList(PPROCINFOMAP prolist, BYTE * pHave);
	BOOL GetProcList2(PPROCINFOMAP * promap, BYTE * pHave);
	BOOL GetProcList3(PPROCINFOMAP * promap, BYTE * pHave);


	PROCINFOMAP m_ProInfos;
};

