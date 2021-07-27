#include "StdAfx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <windows.h>
//#include <versionhelpers.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include<afxtempl.h>

struct format_params;


DWORD get_volume_id ();
DWORD get_fat_size_sectors ( DWORD DskSize, DWORD ReservedSecCnt, DWORD SecPerClus, DWORD NumFATs, DWORD BytesPerSect );
int format_volume ( LPCTSTR, bool, ULONG, ULONG, ULONG);
int get_volume_capacity(LPCTSTR);
int test();

