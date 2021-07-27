//  need to include WinDDK in project
#pragma once
#include "StdAfx.h"
//#include "devioctl.h"
#include <Windows.h>
#include "SCSI.h"
#include <WinIoCtl.h>
#include <ntddscsi.h>
#include <cstddef>
typedef struct _SCSI_PASS_THROUGH_DIRECT_WITH_REQSENSE
{
	SCSI_PASS_THROUGH_DIRECT sptd;
	DWORD filler;	// align abRequestSense to DWORD boundary
	BYTE abRequestSense[32];
} SCSI_PASS_THROUGH_DIRECT_WITH_REQSENSE, *PSCSI_PASS_THROUGH_DIRECT_WITH_REQSENSE;

//struct _stCDB
//{
//	BYTE bCDB[16];
//};

//  bDirection have 3 type
//  SCSI_IOCTL_DATA_OUT: for write command
//  SCSI_IOCTL_DATA_IN: for read command
//  SCSI_IOCTL_DATA_UNSPECIFIED: for no data command
//  if no data command, set pData to NULL and dwDataXferLen to 0

//  dwTimeout: unit is second

//  return      0: no error
//              other: windows errorcode

DWORD ScsiCmdSend(HANDLE hDev, _stCDB stCDB, BYTE bDirection, BYTE bCdbLen, void *pData, DWORD dwDataXferLen, DWORD dwTimeout);

DWORD ScsiCmdSend(HANDLE hDev, _stCDB stCDB, BYTE bDirection, BYTE bCdbLen, void *pData, DWORD dwDataXferLen, DWORD dwTimeout)
{
	BOOL xAPIStatus = FALSE;
	BYTE abRequestSense[32] = {0};
	DWORD dwByteReturn;

	SCSI_PASS_THROUGH_DIRECT_WITH_REQSENSE sptd = {0};
	sptd.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
	sptd.sptd.PathId = 0;
	sptd.sptd.TargetId = 1;
	sptd.sptd.Lun = 0;
	sptd.sptd.CdbLength = bCdbLen;
	sptd.sptd.DataIn = (BYTE)bDirection;
	sptd.sptd.SenseInfoLength = sizeof(sptd.abRequestSense);
	sptd.sptd.DataTransferLength = dwDataXferLen;
	sptd.sptd.TimeOutValue = dwTimeout;
	sptd.sptd.DataBuffer = (pData == NULL) ? abRequestSense : pData;
	sptd.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_REQSENSE, abRequestSense);

	memcpy(sptd.sptd.Cdb, &stCDB, sizeof(sptd.sptd.Cdb));

	xAPIStatus = DeviceIoControl(hDev,
								IOCTL_SCSI_PASS_THROUGH_DIRECT,
								&sptd,
								sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_REQSENSE),
								&sptd,
								sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_REQSENSE),
								&dwByteReturn,
								FALSE);

	if ((sptd.sptd.ScsiStatus == 0) && (xAPIStatus != 0))
		return 0;

	return GetLastError();
}
