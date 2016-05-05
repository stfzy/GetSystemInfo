#pragma once
#include "..\impl.h"
#include <tcpmib.h>
#include <udpmib.h>
#include <IPHlpApi.h>
class CGetTcpUdpState
{
public:
	
	~CGetTcpUdpState(void);
	static CGetTcpUdpState * GetInstance();
	BOOL GetAllNetConStatus(PTCPVECTOR * tcpvector,PUDPVECTOR * udpvector);
private:
	CGetTcpUdpState(void);
	static CGetTcpUdpState * m_instance;
	TCPVECTOR m_tcpVecotor;
	UDPVECTOR m_udpVecotor;
	PORTMAP m_TcpPortMap;
	PORTMAP m_UdpPortMap;
	PMIB_TCPTABLE_OWNER_PID m_pTcpTable;
	PMIB_UDPTABLE_OWNER_PID m_pUdpTable;
private:
	 TCPCONDATA tp;
	BOOL _InitalizeTcp();
	BOOL _InitalizeUdp();

	void _AnalyticalTcpData(PTCPVECTOR tcpvector, BYTE* pHave);
	void _AnalyticalUdpData(PUDPVECTOR udpvector, BYTE* pHave);

	BOOL _GetTcpTable(PTCPVECTOR tcpvector);
	BOOL _GetUdpTable(PUDPVECTOR tudvector);



};

