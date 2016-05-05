 /*!
  * �ļ����� GetProcList.h
  * �������ڣ�2015/12/30 14:04
  *
  * ���ߣ���ͯ
  * ���䣺shentong@jiangmin.com
  *
  * ժҪ����ȡ�����б������Ϣ���ڴ桢cpuʹ�ã���д�������ʣ��ļ�˵����
  *
  *  
  *
  * ��ע��
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
	LARGE_INTEGER KernelTime;               //CPU�ں�ģʽʹ��ʱ�䣻
	LARGE_INTEGER UserTime;                 //CPU�û�ģʽʹ��ʱ�䣻
	LARGE_INTEGER CreateTime;               //�̴߳���ʱ�䣻
	ULONG         WaitTime;                 //�ȴ�ʱ�䣻
	PVOID         StartAddress;             //�߳̿�ʼ�������ַ��
	CLIENT_ID     ClientId;                 //�̱߳�ʶ����
	KPRIORITY     Priority;                 //�߳����ȼ���
	KPRIORITY     BasePriority;             //�������ȼ���
	ULONG         ContextSwitchCount;       //�����л���Ŀ��
	THREAD_STATE  State;                    //��ǰ״̬��
	KWAIT_REASON  WaitReason;               //�ȴ�ԭ��
}SYSTEM_THREADS, *PSYSTEM_THREADS;



typedef struct _IO_COUNTERS1
{
	LARGE_INTEGER ReadOperationCount;       //I/O��������Ŀ��
	LARGE_INTEGER WriteOperationCount;      //I/Oд������Ŀ��
	LARGE_INTEGER OtherOperationCount;      //I/O����������Ŀ��
	LARGE_INTEGER ReadTransferCount;        //I/O��������Ŀ��
	LARGE_INTEGER WriteTransferCount;       //I/Oд������Ŀ��
	LARGE_INTEGER OtherTransferCount;       //I/O��������������Ŀ��
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
	SIZE_T PeakVirtualSize;                  //����洢��ֵ��С��
	SIZE_T VirtualSize;                      //����洢��С��
	SIZE_T PageFaultCount;                   //ҳ������Ŀ��
	SIZE_T PeakWorkingSetSize;               //��������ֵ��С��
	SIZE_T WorkingSetSize;                   //��������С��
	SIZE_T QuotaPeakPagedPoolUsage;          //��ҳ��ʹ������ֵ��
	SIZE_T QuotaPagedPoolUsage;              //��ҳ��ʹ����
	SIZE_T QuotaPeakNonPagedPoolUsage;       //�Ƿ�ҳ��ʹ������ֵ��
	SIZE_T QuotaNonPagedPoolUsage;           //�Ƿ�ҳ��ʹ����
	SIZE_T PagefileUsage;                    //ҳ�ļ�ʹ�������
	SIZE_T PeakPagefileUsage;                //ҳ�ļ�ʹ�÷�ֵ��
}VM_COUNTERS, *PVM_COUNTERS;
typedef struct _SYSTEM_PROCESSES
{
	ULONG          NextEntryDelta;          //���ɽṹ���е�ƫ������
	ULONG          ThreadCount;             //�߳���Ŀ��
	ULONG          Reserved1[6];
	LARGE_INTEGER  CreateTime;              //����ʱ�䣻
	LARGE_INTEGER  UserTime;                //�û�ģʽ(Ring 3)��CPUʱ�䣻
	LARGE_INTEGER  KernelTime;              //�ں�ģʽ(Ring 0)��CPUʱ�䣻
	UNICODE_STRING ProcessName;             //�������ƣ�
	KPRIORITY      BasePriority;            //��������Ȩ��
	ULONG          ProcessId;               //���̱�ʶ����
	ULONG          InheritedFromProcessId;  //�����̵ı�ʶ����
	ULONG          HandleCount;             //�����Ŀ��
	ULONG          Reserved2[2];
	VM_COUNTERS    VmCounters;              //����洢���Ľṹ�����£�
	IO_COUNTERS1    IoCounters;              //IO�����ṹ�����£�
	SYSTEM_THREADS Threads[1];              //��������̵߳Ľṹ���飬���£�
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

