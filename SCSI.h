
struct _stCDB
{
	BYTE bCDB[16];
};

extern DWORD ScsiCmdSend(HANDLE hDev, _stCDB stCDB, BYTE bDirection, BYTE bCdbLen, void *pData, DWORD dwDataXferLen, DWORD dwTimeout = 60);