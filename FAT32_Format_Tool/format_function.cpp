#include "StdAfx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "SCSI.h"
#include <windows.h>
//#include <versionhelpers.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include<afxtempl.h>
#include <algorithm> 

//static unsigned ALIGNING_SIZE = 1024 * 1024;


#pragma pack(push, 1)
struct MBR_BOOTSECTOR
{
	BYTE BootCode[446];
	BYTE BootFlag;
	BYTE CHSofBegin[3];
	BYTE FileSystemFlag;
	BYTE CHSofEnd[3];
	DWORD LBAofFirstSec;
	DWORD TotalSec_partition;
};

struct CAPACITY
{
	DWORD TotalSec_disk;
	DWORD BytePerSec;
};

struct FAT_BOOTSECTOR32
{
	// Common fields.
	BYTE sJmpBoot[3];// = { 0xEB, 0x58, 0x90 };
	BYTE sOEMName[8];// = { 'M','S','D','O','S','5','.','0' };
	WORD wBytsPerSec;
	BYTE bSecPerClus;
	WORD wRsvdSecCnt;
	BYTE bNumFATs;// = 2;
	WORD wRootEntCnt;// = 0;
	WORD wTotSec16;// = 0;
	BYTE bMedia;// = 0xF8;
	WORD wFATSz16;// = 0;
	WORD wSecPerTrk;
	WORD wNumHeads;
	DWORD dHiddSec;
	DWORD dTotSec32;    //20-23
	// Fat 32/16 only
	DWORD dFATSz32;
	WORD wExtFlags;// = 0;
	WORD wFSVer;// = 0;
	DWORD dRootClus;// = 2;
	WORD wFSInfo;// = 1;
	WORD wBkBootSec;// = 6;
	BYTE Reserved[12];// = {};
	//
	BYTE bDrvNum;// = 0x80;  //40
	BYTE Reserved1;// = 0;
	BYTE bBootSig;// = 0x29;
	DWORD dBS_VolID;
	BYTE sVolLab[11];// = { 'N','O',' ','N','A','M','E',' ',' ',' ',' ' };
	BYTE sBS_FilSysType[8];// = { 'F','A','T','3','2',' ',' ',' ' };
};

struct FAT_FSINFO
{
	DWORD dLeadSig;// = 0x41615252;
	BYTE sReserved1[480];// = {};
	DWORD dStrucSig;// = 0x61417272;
	DWORD dFree_Count;// = 0xFFFFFFFF;
	DWORD dNxt_Free;// = 0xFFFFFFFF;
	BYTE sReserved2[12];// = {};
	DWORD dTrailSig;// = 0xAA550000;
};

struct FAT_DIRECTORY
{
	char     DIR_Name[8+3];
	uint8_t  DIR_Attr;
	uint8_t  DIR_NTRes;
	uint8_t  DIR_CrtTimeTenth;
	uint16_t DIR_CrtTime;
	uint16_t DIR_CrtDate;
	uint16_t DIR_LstAccDate;
	uint16_t DIR_FstClusHI;
	uint16_t DIR_WrtTime;
	uint16_t DIR_WrtDate;
	uint16_t DIR_FstClusLO;
	uint32_t DIR_FileSize;
	enum : uint8_t
	{
		ATTR_VOLUME_ID = 0x8
	};
};
static_assert( sizeof( FAT_DIRECTORY ) == 32, "" );

#pragma pack(pop)

/*
CALCULATING THE VOLUME SERIAL NUMBER
For example, say a disk was formatted on 26 Dec 95 at 9:55 PM and 41.94
seconds.  DOS takes the date and time just before it writes it to the
disk.
Low order word is calculated:               Volume Serial Number is:
    Month & Day         12/26   0c1ah
    Sec & Hundrenths    41:94   295eh               3578:1d02
                                -----
                                3578h
High order word is calculated:
    Hours & Minutes     21:55   1537h
    Year                1995    07cbh
                                -----
                                1d02h
*/
DWORD get_volume_id ( )
{
    SYSTEMTIME s;

    GetLocalTime( &s );

	WORD lo = s.wDay + ( s.wMonth << 8 );
	WORD tmp = (s.wMilliseconds/10) + (s.wSecond << 8 );
    lo += tmp;

	WORD hi = s.wMinute + ( s.wHour << 8 );
    hi += s.wYear;
   
    return lo + ( hi << 16 );
}

struct format_params
{
	int sectors_per_cluster;// = cluster_size/512;        // can be zero for default or 1,2,4,8,16,32 or 64
	bool make_protected_autorun;//  = false;
	bool all_yes;// = false;
	PCSTR volume_label;// = nullptr;
};

DWORD get_fat_size_sectors ( DWORD DskSize, DWORD ReservedSecCnt, DWORD SecPerClus, DWORD NumFATs, DWORD BytesPerSect )
{
    ULONGLONG FatElementSize = 4;
	ULONGLONG Numerator = FatElementSize * ( DskSize - ReservedSecCnt );
	ULONGLONG Denominator = ( SecPerClus * BytesPerSect ) + ( FatElementSize * NumFATs );
	ULONGLONG FatSz = Numerator / Denominator;
    // round up
    FatSz += 1;

	//ULONG align_sector_count = ALIGNING_SIZE / BytesPerSect;
	//FatSz = ( FatSz + align_sector_count - 1 ) / align_sector_count * align_sector_count;

    return (DWORD)FatSz;
}


int zero_sectors ( HANDLE hDevice, DWORD Sector, DWORD BytesPerSect, DWORD NumSects )
{
	// Clear 512*n Bytes per iteration
	DWORD n = 128;
	BYTE* pZeroSect = (BYTE*) VirtualAlloc( NULL, BytesPerSect*n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	DWORD Current_Sec = 0;

    while ( Current_Sec < NumSects )
    {
		int scsi_status;
		_stCDB WRITE_CDB_Zero = {0x2A,0,(Current_Sec & 0xff000000) >> 24,
										(Current_Sec & 0x00ff0000) >> 16,
										(Current_Sec & 0x0000ff00) >> 8,
										(Current_Sec & 0x000000ff),0,0,n,0};
		scsi_status = ScsiCmdSend( hDevice, WRITE_CDB_Zero, SCSI_IOCTL_DATA_OUT, 10, pZeroSect, 512*n, 10);
		if(scsi_status != 0) return scsi_status;
		Current_Sec += n;
    }

	return 0;
}



int get_volume_capacity(LPCTSTR vol){
	DWORD cbRet;
    BOOL bRet;
	DWORD error; 

	HANDLE hDevice = CreateFile(vol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if ( hDevice == INVALID_HANDLE_VALUE ){
		error = GetLastError();
		return error;
	}
	bRet = DeviceIoControl( hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );
	if( !bRet ){
		error = GetLastError();
		return error;
	}

	DWORD scsi_status;
	CAPACITY* pCAPACITY = (CAPACITY*) VirtualAlloc ( NULL, 512, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	_stCDB READ_CDB_CAPACITY = {0x25,0,0,0,0,0,0,0,1,0};
	scsi_status = ScsiCmdSend( hDevice, READ_CDB_CAPACITY, SCSI_IOCTL_DATA_IN, 10, pCAPACITY, 512, 5);
	if(scsi_status != 0) return scsi_status;
	DWORD TotalSec_disk_rev;
	TotalSec_disk_rev = (pCAPACITY->TotalSec_disk & 0x000000ff) << 24 |
						(pCAPACITY->TotalSec_disk & 0x0000ff00) << 8 |
						(pCAPACITY->TotalSec_disk & 0x00ff0000) >> 8 |
						(pCAPACITY->TotalSec_disk & 0xff000000) >> 24;

	bRet = DeviceIoControl( hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );
	if ( !bRet ) return -9;

	bRet = DeviceIoControl( hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );
	if ( !bRet ) return -10;
        
    // CloseDevice
    CloseHandle( hDevice );


	return TotalSec_disk_rev;
}


 int format_volume (LPCTSTR vol, bool MBR_flag, ULONG cluster_size, ULONG Offset_of_FAT, ULONG Offset_of_partition){
	DWORD cbRet;
    BOOL bRet;
    DISK_GEOMETRY         dgDrive;
	PARTITION_INFORMATION  piDrive = {};
	PARTITION_INFORMATION_EX xpiDrive;
	BOOL bGPTMode = FALSE;
    DWORD VolumeId= get_volume_id( );
	DWORD error; 
	DWORD scsi_status;

	// open the drive
	HANDLE hDevice = CreateFile(vol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 

	if ( hDevice == INVALID_HANDLE_VALUE ){
		error = GetLastError();
		return error;
	}

	//bRet= DeviceIoControl(hDevice, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &cbRet, NULL);
	//if( !bRet ){
	//	error = GetLastError();
	//	return error;
	//}

	// lock it
	bRet = DeviceIoControl( hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );
	if( !bRet ){
		error = GetLastError();
		return error;
	}
	// work out drive params
	bRet = DeviceIoControl ( hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dgDrive, sizeof(dgDrive), &cbRet, NULL);
	if( !bRet ){
		error = GetLastError();
		return error;
	}


	bRet = DeviceIoControl( hDevice, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &piDrive, sizeof(piDrive), &cbRet, NULL);
	if( !bRet ){
		// IOCTL_DISK_GET_PARTITION_INFO failed, trying IOCTL_DISK_GET_PARTITION_INFO_EX
		bRet = DeviceIoControl ( hDevice, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &xpiDrive, sizeof(xpiDrive), &cbRet, NULL);
		if(!bRet){
			error = GetLastError();
			return error;
		}
		piDrive.StartingOffset.QuadPart = xpiDrive.StartingOffset.QuadPart;
		piDrive.PartitionLength.QuadPart = xpiDrive.PartitionLength.QuadPart;
		piDrive.HiddenSectors = (DWORD) (xpiDrive.StartingOffset.QuadPart / dgDrive.BytesPerSector);
		
		bGPTMode = xpiDrive.PartitionStyle != PARTITION_STYLE_MBR;
	}

	ULONG BytesPerSect = dgDrive.BytesPerSector;



	CAPACITY* pCAPACITY = (CAPACITY*) VirtualAlloc ( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	_stCDB READ_CDB_CAPACITY = {0x25,0,0,0,0,0,0,0,1,0};
	scsi_status = ScsiCmdSend( hDevice, READ_CDB_CAPACITY, SCSI_IOCTL_DATA_IN, 10, pCAPACITY, 512, 5);
	if(scsi_status != 0) return scsi_status;

	MBR_BOOTSECTOR* pMBRBootSect = (MBR_BOOTSECTOR*) VirtualAlloc ( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	new ( pMBRBootSect ) MBR_BOOTSECTOR;

	
		
		DWORD TotalSec_disk_rev;
		TotalSec_disk_rev = (pCAPACITY->TotalSec_disk & 0x000000ff) << 24 |
							(pCAPACITY->TotalSec_disk & 0x0000ff00) << 8 |
							(pCAPACITY->TotalSec_disk & 0x00ff0000) >> 8 |
							(pCAPACITY->TotalSec_disk & 0xff000000) >> 24;

		pMBRBootSect->BootFlag       = 0x00;     // Boot Flag
		pMBRBootSect->CHSofBegin[0]  = 0x20;     // CHS Address of First Sector in the Partition
		pMBRBootSect->CHSofBegin[1]  = 0x21;     // ..
		pMBRBootSect->CHSofBegin[2]  = 0x00;     // ..
		pMBRBootSect->FileSystemFlag = 0x0C;     // FAT32 File System Type Code
		pMBRBootSect->CHSofEnd[0]    = 0xFE;     // CHS Address of Last Sector in the Partition
		pMBRBootSect->CHSofEnd[1]    = 0xFF;     // ..
		pMBRBootSect->CHSofEnd[2]    = 0xFF;     // ..

		// LBA of First sector in the Partition
		// At least followed by Boot Sector
		pMBRBootSect->LBAofFirstSec = (DWORD) Offset_of_partition > 0x00000001 ? Offset_of_partition : 0x00000001;

		pMBRBootSect->TotalSec_partition = TotalSec_disk_rev - pMBRBootSect->LBAofFirstSec;   // Number of Sectors in the Partition
		((BYTE*)pMBRBootSect)[BytesPerSect-2] = 0x55;
		((BYTE*)pMBRBootSect)[BytesPerSect-1] = 0xAA;
	
		// Checks on Disk Size
		// low end limit - 65536 sectors
		if ( pMBRBootSect->TotalSec_partition > 0xFFFFFFFF )
		{
			// I suspect that most FAT32 implementations would mount this volume just fine, but the
			// spec says that we shouldn't do this, so we won't
			return -1;
		}
		if ( pMBRBootSect->TotalSec_partition < 65536 )
		{
			// I suspect that most FAT32 implementations would mount this volume just fine, but the
			// spec says that we shouldn't do this, so we won't
			return -1;
		}

	
	


	//  Allocate Memory for FAT Parameters
	FAT_BOOTSECTOR32* pFAT32BootSect = (FAT_BOOTSECTOR32*) VirtualAlloc ( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	FAT_FSINFO* pFAT32FsInfo = (FAT_FSINFO*) VirtualAlloc( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	DWORD* pFirstSectOfFat = (DWORD*) VirtualAlloc( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	FAT_DIRECTORY* pFAT32Directory = (FAT_DIRECTORY*)VirtualAlloc( NULL, BytesPerSect, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if( !pFAT32BootSect || !pFAT32FsInfo || !pFirstSectOfFat || !pFAT32Directory )
		return -1;

	new ( pFAT32BootSect ) FAT_BOOTSECTOR32;
	new ( pFAT32FsInfo ) FAT_FSINFO;


	/////////////////////////////////////
	/////////////////////////////////////
	/////////////////////////////////////
	/// Fill out the FAT boot sector  ///
	/////////////////////////////////////
	/////////////////////////////////////
	/////////////////////////////////////
	pFAT32BootSect->sJmpBoot[0] = 0xEB ;
	pFAT32BootSect->sJmpBoot[1] = 0x58 ;
	pFAT32BootSect->sJmpBoot[2] = 0x90 ;
	pFAT32BootSect->sOEMName[0] = 'M' ;
	pFAT32BootSect->sOEMName[1] = 'S' ;
	pFAT32BootSect->sOEMName[2] = 'D' ;
	pFAT32BootSect->sOEMName[3] = 'O' ;
	pFAT32BootSect->sOEMName[4] = 'S' ;
	pFAT32BootSect->sOEMName[5] = '5' ;
	pFAT32BootSect->sOEMName[6] = '.' ;
	pFAT32BootSect->sOEMName[7] = '0' ;
	pFAT32BootSect->wBytsPerSec = (WORD) BytesPerSect;
	ULONG SectorsPerCluster = cluster_size/BytesPerSect;
	pFAT32BootSect->bSecPerClus = (BYTE) (SectorsPerCluster & 0x000000FF);
	pFAT32BootSect->wRsvdSecCnt = (WORD) Offset_of_FAT > 0x000D ? Offset_of_FAT : 0x000D; // At least 13
	pFAT32BootSect->bNumFATs = 2;
	pFAT32BootSect->wRootEntCnt = 0;
	pFAT32BootSect->wTotSec16 = 0;
	pFAT32BootSect->bMedia = 0xF8;
	pFAT32BootSect->wFATSz16 = 0;
	pFAT32BootSect->wSecPerTrk = (WORD) dgDrive.SectorsPerTrack;
	pFAT32BootSect->wNumHeads = (WORD) dgDrive.TracksPerCylinder;
    pFAT32BootSect->dHiddSec = MBR_flag ? pMBRBootSect->LBAofFirstSec : 0;

   // ULONG TotalSectors = (DWORD)  (piDrive.PartitionLength.QuadPart/dgDrive.BytesPerSector);
    pFAT32BootSect->dTotSec32 = pMBRBootSect->TotalSec_partition;

	ULONG FatSize = get_fat_size_sectors(pFAT32BootSect->dTotSec32, pFAT32BootSect->wRsvdSecCnt, pFAT32BootSect->bSecPerClus, pFAT32BootSect->bNumFATs, BytesPerSect );
    pFAT32BootSect->dFATSz32 = FatSize;

	pFAT32BootSect->wExtFlags = 0;
	pFAT32BootSect->wFSVer = 0;
	pFAT32BootSect->dRootClus = 2;
	pFAT32BootSect->wFSInfo = 1;
	pFAT32BootSect->wBkBootSec = 6;
	//pFAT32BootSect->Reserved[0] = 0;
	//pFAT32BootSect->Reserved[1] = 0;
	//pFAT32BootSect->Reserved[2] = 0;
	//pFAT32BootSect->Reserved[3] = 0;
	//pFAT32BootSect->Reserved[4] = 0;
	//pFAT32BootSect->Reserved[5] = 0;
	//pFAT32BootSect->Reserved[6] = 0;
	//pFAT32BootSect->Reserved[7] = 0;
	//pFAT32BootSect->Reserved[8] = 0;
	//pFAT32BootSect->Reserved[9] = 0;
	//pFAT32BootSect->Reserved[10] = 0;
	//pFAT32BootSect->Reserved[11] = 0;	
	//
	pFAT32BootSect->bDrvNum = 0x80;  //40
	pFAT32BootSect->Reserved1 = 0;
	pFAT32BootSect->bBootSig = 0x29;
	pFAT32BootSect->dBS_VolID = VolumeId;
	pFAT32BootSect->sVolLab[0] = 'N';
	pFAT32BootSect->sVolLab[1] = 'O';
	pFAT32BootSect->sVolLab[2] = ' ';
	pFAT32BootSect->sVolLab[3] = 'N';
	pFAT32BootSect->sVolLab[4] = 'A';
	pFAT32BootSect->sVolLab[5] = 'M';
	pFAT32BootSect->sVolLab[6] = 'E';
	pFAT32BootSect->sVolLab[7] = ' ';
	pFAT32BootSect->sVolLab[8] = ' ';
	pFAT32BootSect->sVolLab[9] = ' ';
	pFAT32BootSect->sVolLab[10] = ' ';
	pFAT32BootSect->sBS_FilSysType[0] = 'F';
	pFAT32BootSect->sBS_FilSysType[1] = 'A';
	pFAT32BootSect->sBS_FilSysType[2] = 'T';
	pFAT32BootSect->sBS_FilSysType[3] = '3';
	pFAT32BootSect->sBS_FilSysType[4] = '2';
	pFAT32BootSect->sBS_FilSysType[5] = ' ';
	pFAT32BootSect->sBS_FilSysType[6] = ' ';
	pFAT32BootSect->sBS_FilSysType[7] = ' ';

	if ( BytesPerSect != 512 )
	{
		((BYTE*)pFAT32BootSect)[BytesPerSect-2] = 0x55;
		((BYTE*)pFAT32BootSect)[BytesPerSect-1] = 0xaa;
	}
	else
	{
		((BYTE*)pFAT32BootSect)[510] = 0x55;
		((BYTE*)pFAT32BootSect)[511] = 0xaa;
	}


	// First FAT Sector
    pFirstSectOfFat[0] = 0x0ffffff8;  // Reserved cluster 1 media id in low byte
    pFirstSectOfFat[1] = 0x0fffffff;  // Reserved cluster 2 EOC
    pFirstSectOfFat[2] = 0x0fffffff;  // end of cluster chain for root dir


	// Write boot sector, fats
    // Sector 0 Boot Sector
    // Sector 1 FSInfo 
    // Sector 2 More boot code - we write zeros here
    // Sector 3 unused
    // Sector 4 unused
    // Sector 5 unused
    // Sector 6 Backup boot sector
    // Sector 7 Backup FSInfo sector
    // Sector 8 Backup 'more boot code'
    // zero'd sectors upto ReservedSectCount
    // FAT1  ReservedSectCount to ReservedSectCount + FatSize
    // FAT2  ReservedSectCount + FatSize to ReservedSectCount + FatSize * 2
    // RootDir - allocated to cluster2

	ULONG UserAreaSize = pMBRBootSect->TotalSec_partition - pFAT32BootSect->wRsvdSecCnt - ( pFAT32BootSect->bNumFATs*FatSize);
	ULONGLONG ClusterCount = UserAreaSize/SectorsPerCluster;
	// Sanity check for a cluster count of >2^28, since the upper 4 bits of the cluster values in 
    // the FAT are reserved.
    if (  ClusterCount > 0x0FFFFFFF )
    {
        return -2;
    }
	// Sanity check - < 64K clusters means that the volume will be misdetected as FAT16
	if ( ClusterCount < 65536 )
	{
		return -3;
	}
	// Convert the cluster count into a Fat sector count, and check the fat size value
	ULONGLONG FatNeeded = ClusterCount * 4;
    FatNeeded += (BytesPerSect-1);
    FatNeeded /= BytesPerSect;
    if ( FatNeeded > FatSize )
    {
        return -4;
    }

	/////////////////////////////////
	/////////////////////////////////
	/////////////////////////////////
	// Fill out the FS Infomation  //
	/////////////////////////////////
	/////////////////////////////////
	/////////////////////////////////
	pFAT32FsInfo->dLeadSig= 0x41615252;
	for(int i = 0; i < 480; i++)
		pFAT32FsInfo->sReserved1[i] = 0;
	pFAT32FsInfo->dStrucSig = 0x61417272;
	pFAT32FsInfo->dFree_Count = (UserAreaSize/SectorsPerCluster)-1;
	pFAT32FsInfo->dNxt_Free = 3;
	for(int i = 0; i < 12; i++)
		pFAT32FsInfo->sReserved2[i] = 0;
	pFAT32FsInfo->dTrailSig = 0xAA550000;

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////             Start Formating !!             //////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	ULONG SystemAreaSize =  pFAT32BootSect->wRsvdSecCnt + 
							( pFAT32BootSect->bNumFATs * FatSize ) + 
							SectorsPerCluster + 
							(DWORD) piDrive.HiddenSectors;
	int success_clear = zero_sectors( hDevice, 0, BytesPerSect, SystemAreaSize );
	if (success_clear != 0)
		return -5;

	// Write MBR Boot Sector

	if(MBR_flag == 1){
	_stCDB WRITE_CDB_MBR_Boot_Sec = {0x2A,0,0,0,0,0,0,0,1,0};
	scsi_status = ScsiCmdSend( hDevice, WRITE_CDB_MBR_Boot_Sec, SCSI_IOCTL_DATA_OUT, 10, pMBRBootSect, 512, 5);
	if(scsi_status != 0) return scsi_status;
	}

	// Now we should write the boot sector and fsinfo twice, once at 0 and once at the backup boot sect position
	for( int i = 0; i < 2; i++ )
	{
		DWORD SectorStart = ( i == 0 ) ? pFAT32BootSect->dHiddSec : pFAT32BootSect->dHiddSec + pFAT32BootSect->wBkBootSec;
		_stCDB WRITE_CDB_FAT_Boot_Sec = {0x2A,0,(SectorStart & 0xff000000) >> 24,
												(SectorStart & 0x00ff0000) >> 16,
												(SectorStart & 0x0000ff00) >> 8,
												(SectorStart & 0x000000ff),0,0,1,0};
		scsi_status = ScsiCmdSend( hDevice, WRITE_CDB_FAT_Boot_Sec, SCSI_IOCTL_DATA_OUT, 10, pFAT32BootSect, 512, 5);
		if(scsi_status != 0) return scsi_status;
		SectorStart += 1;
		_stCDB WRITE_CDB_FAT_FS_INFO = {0x2A,0,(SectorStart & 0xff000000) >> 24,
											   (SectorStart & 0x00ff0000) >> 16,
											   (SectorStart & 0x0000ff00) >> 8,
											   (SectorStart & 0x000000ff),0,0,1,0};
		scsi_status = ScsiCmdSend( hDevice, WRITE_CDB_FAT_FS_INFO, SCSI_IOCTL_DATA_OUT, 10, pFAT32FsInfo, 512, 5);
		if(scsi_status != 0) return scsi_status;

	}

	// Write the first fat sector in the right places
	for( int i = 0; i < pFAT32BootSect->bNumFATs; i++ )
	{
		int SectorStart = pFAT32BootSect->dHiddSec + pFAT32BootSect->wRsvdSecCnt + ( i * FatSize );
		_stCDB WRITE_CDB_FIRST_FAT = {0x2A,0,(SectorStart & 0xff000000) >> 24,
											 (SectorStart & 0x00ff0000) >> 16,
											 (SectorStart & 0x0000ff00) >> 8,
											 (SectorStart & 0x000000ff),0,0,1,0};
		scsi_status = ScsiCmdSend( hDevice, WRITE_CDB_FIRST_FAT, SCSI_IOCTL_DATA_OUT, 10, pFirstSectOfFat, 512, 5);
		if(scsi_status != 0) return scsi_status;
		
	}

	//if ( !bGPTMode && piDrive.HiddenSectors > 0)
	//{
	//SET_PARTITION_INFORMATION spiDrive = { PARTITION_FAT32_XINT13 };
	//
	//bRet = DeviceIoControl ( hDevice, IOCTL_DISK_SET_PARTITION_INFO, &spiDrive, sizeof(spiDrive), NULL, 0, &cbRet, NULL);
	//if ( !bRet )return -8;  
	//}


	bRet = DeviceIoControl( hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );
	if ( !bRet ) return -9;

	bRet = DeviceIoControl( hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &cbRet, NULL );
	if ( !bRet ) return -10;
        
    // CloseDevice
    CloseHandle( hDevice );


	return 0;
}






int test(){
	return 100;
}