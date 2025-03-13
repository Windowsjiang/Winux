// CsrssWalker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <TLHELP32.H>
#include "CsrssStruct.h"
#include "psapi.h"

#pragma comment(lib,"psapi.lib")

#define IMAGEFILENAMELEN 56
typedef struct  _PROC_NAME_INFO
{
	ULONG ProcessId;
	char  ImageName[IMAGEFILENAMELEN];
}PROC_NAME_INFO,*PPROC_NAME_INFO;

void  ShowProcessByWalkCsrssProcessLink(ULONG CsrssPid,PVOID CsrssRootProcessPointer);
BOOL  EnableDebugPrivilege();
ULONG GetCsrssProcessId();
ULONG GetModuleHandleByName(ULONG pid,char *szModuleName);
ULONG GetCsrssRootProcessPointer(ULONG CsrssPid,HMODULE CsrsrvBase);
ULONG GetCsrssRootProcessPointerOffset();
VOID  CollectProcessNameInfo();
char *GetProcessNameByPid(ULONG pid);

ULONG ProcessNameCnt=0;
PPROC_NAME_INFO ProcessNameInfo=NULL;

int main(int argc, char* argv[])
{
	ULONG CsrssPid=0;
	ULONG CsrsrvBase=0;
	ULONG CsrssRootProcessPointerOffset=0;
	PVOID CsrssRootProcessPointer=0;
	printf("\t\t\tCsrssWalker by [achillis]\n");
	//����SE_DEBUG_PRIVILEGE�����ڴ�Csrss.exe
	EnableDebugPrivilege();
	CsrssPid=GetCsrssProcessId();
	if (CsrssPid)
	{
		printf("[*]Get Csrss.exe pid=%d\n",CsrssPid);
	}
	else
	{
		printf("[-]Get Csrss.exe pid Failed!\n");
		return 0;
	}
	CsrsrvBase=GetModuleHandleByName(CsrssPid,"csrsrv.dll");
	if (CsrsrvBase)
	{
		printf("[*]Get Csrsrv.dll Base=0x%08X\n",CsrsrvBase);
	}
	else
	{
		printf("[-]Get Csrsrv.dll Base Failed!\n");
		return 0;
	}
	CsrssRootProcessPointerOffset=GetCsrssRootProcessPointerOffset();
	if (CsrssRootProcessPointerOffset)
	{
		printf("[*]Get CsrssRootProcess Offset =0x%08X\n",CsrssRootProcessPointerOffset);
	}
	else
	{
		printf("[-]Get CsrssRootProcess Offset Failed!\n");
		return 0;
	}
	CsrssRootProcessPointer=(char*)CsrsrvBase+CsrssRootProcessPointerOffset;
	printf("[*]Get CsrssRootProcess Pointer=0x%08X\n",CsrssRootProcessPointer);
	CollectProcessNameInfo();
	ShowProcessByWalkCsrssProcessLink(CsrssPid,CsrssRootProcessPointer);
	getchar();
	return 0;
}

void ShowProcessByWalkCsrssProcessLink(ULONG CsrssPid,PVOID CsrssRootProcessPointer)
{
	HANDLE hProcess=NULL;
	ULONG ProcCnt=0,HiddenCnt=0;;
	PCSR_PROCESS pCsrssRootProcess=NULL;
	PCSR_PROCESS pProcessInfo;
	PLIST_ENTRY pProcessList,pNext;
	ULONG ReadSize;
	hProcess=OpenProcess(PROCESS_VM_READ,FALSE,CsrssPid);
	if (!hProcess)
	{
		printf("[-]Open Csrss.exe Failed.\n");
		return;
	}
	ReadProcessMemory(hProcess,CsrssRootProcessPointer,&pCsrssRootProcess,4,&ReadSize);
	printf("[*]Get CsrssRootProcess Value  =0x%08X\n",pCsrssRootProcess);
	pProcessInfo=(PCSR_PROCESS)VirtualAlloc(NULL,sizeof(CSR_PROCESS),MEM_COMMIT,PAGE_READWRITE);
	if (!pProcessInfo)
	{
		printf("[-]Alloc Buffer Failed.\n");
		return;
	}
	ReadProcessMemory(hProcess,pCsrssRootProcess,pProcessInfo,sizeof(CSR_PROCESS),&ReadSize);
	printf("[*]Csrss.UniqueProcessId=%d  Csrss.UniqueThreadId=%d\n",
		pProcessInfo->ClientId.UniqueProcess,pProcessInfo->ClientId.UniqueThread);
	//���濪ʼ����CsrssProcessLink
	pNext=pProcessInfo->ListLink.Flink;
	pProcessList=(PLIST_ENTRY)((char*)pCsrssRootProcess+sizeof(CLIENT_ID));
	//printf("pProcessList=0x%08X\n",pProcessList);
	printf("\n#PID       ImageFileName\n");
	printf("=====    ========================\n");
	while (pNext!=pProcessList)
	{
		//printf("[%2d]pNext=0x%08X\t",ProcCnt++,pNext);
		ReadProcessMemory(hProcess,(char*)pNext-sizeof(CLIENT_ID),pProcessInfo,sizeof(CSR_PROCESS),&ReadSize);
		printf("%4d     ",pProcessInfo->ClientId.UniqueProcess);
		ProcCnt++;
		char *NameInfo=GetProcessNameByPid((ULONG)pProcessInfo->ClientId.UniqueProcess);
		if (NameInfo)
		{
			printf("%s\n",NameInfo);
		}
		else
		{
			printf("<??\>\n");
			HiddenCnt++;
		}
		pNext=pProcessInfo->ListLink.Flink;
	}
	printf("\nProcesses/Hidden : %d / %d\n",ProcCnt,HiddenCnt);
	if (pProcessInfo)
		VirtualFree(pProcessInfo,sizeof(CSR_PROCESS),MEM_RELEASE);
	if (ProcessNameInfo)
		VirtualFree(ProcessNameInfo,ProcessNameCnt*sizeof(PROC_NAME_INFO),MEM_RELEASE);
	return;
}

BOOL EnableDebugPrivilege() //��������������Ȩ�ޣ�������SE_DEBUG_NAME
{ 
	TOKEN_PRIVILEGES tkp; 
	HANDLE hToken; 
	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))     //�򿪵�ǰ����ʧ�� 
		return FALSE; 
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tkp.Privileges[0].Luid); //�鿴��ǰȨ��
	tkp.PrivilegeCount = 1; 
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); //����Ȩ�ޣ���������
	return TRUE; 
}

//����Csrss.exe���̣�Vistaע���в�ֹһ��Csrss.exe���̣�ע�⴦��
ULONG GetCsrssProcessId()
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapShot=NULL;
	ULONG CsrssPid=0;
	ZeroMemory(&pe32,sizeof(PROCESSENTRY32));
	pe32.dwSize=sizeof(PROCESSENTRY32);
	hSnapShot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if (hSnapShot==INVALID_HANDLE_VALUE)
	{
		printf("Create Process SnapShot Failed!\n");
		return 0;
	}
	if (Process32First(hSnapShot,&pe32))
	{
		do 
		{
			if (!stricmp(pe32.szExeFile,"csrss.exe"))
			{
				CsrssPid=pe32.th32ProcessID;
				break;
			}
		} while(Process32Next(hSnapShot,&pe32));
	}
	CloseHandle(hSnapShot);
	return CsrssPid;
}


ULONG GetModuleHandleByName(ULONG pid,char *szModuleName)
{
	/*
	�ú����൱��GetModuleHandle()��������ǿ��,�������ڲ������������е�ģ����Ϣ
	*/
	HANDLE hProcess=NULL;
	HMODULE hMods[1024];
	char szModName[MAX_PATH];
	DWORD cbNeeded=0;
	ULONG i;
	char *p;
	ULONG ModuleBase=0;
	hProcess=OpenProcess(PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,FALSE,pid);
	if (!hProcess)
	{
		printf("OpenProcess %d Failed\n",pid);
		return 0;
	}
	if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
            if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,sizeof(szModName)))
            {
                p=strrchr(szModName,'\\')+1;
				if (!stricmp(p,szModuleName))
				{
					//printf("\t%s (0x%08X)\n", p, hMods[i] );
					ModuleBase= (ULONG)hMods[i];
				}
				
            }
        }
    }
	CloseHandle( hProcess );
	return ModuleBase;
}

//�Լ�����һ��CSRSRV.DLL����λ���ƫ��
ULONG GetCsrssRootProcessPointerOffset()
{
	char szDllName[MAX_PATH];
	char *pfnCsrLockProcessByClientId;
	HMODULE hCsrsrv=NULL;
	ULONG Offset;
	GetSystemDirectory(szDllName,MAX_PATH);
	strcat(szDllName,"\\csrsrv.dll");
	hCsrsrv=LoadLibraryEx(szDllName,NULL,DONT_RESOLVE_DLL_REFERENCES);
	if (hCsrsrv)
	{
		//printf("Csrsrv ModuleBase=0x%08X\n",hCsrsrv);
		pfnCsrLockProcessByClientId=(char*)GetProcAddress(hCsrsrv,"CsrLockProcessByClientId");
		//printf("CsrLockProcessByClientId=0x%08X\n",pfnCsrLockProcessByClientId);
		/*
		75AA52ED    8B35 1C89AA75          mov esi,dword ptr ds:[75AA891C]
		75AA52F3    83C6 08                add esi,8
		*/
		//�����������������CsrssRootProcessָ��ĵ�ַ,�������75AA891C
		//һ��С���ɣ�ȷ��������ƥ���������ʱ����Ҫ�����Ĵ�����Ϣ(�������esi)��ֻ����������Ϣ���ɣ�������ǿͨ����
		//����XP��CSRSRV.DLL���ҵ������룬ͬ��������Vista��CSSRV.DLL
		for (int i=0;i<0x50;i++)
		{
			BYTE *p=(BYTE*)pfnCsrLockProcessByClientId+i;
			if (*p==0x8B && *(p+6)==0x83 && *(p+8)==0x08)
			{
				Offset=*(ULONG*)(p+2);
				Offset=Offset-(ULONG)hCsrsrv;
				//printf("Offset=0x%08X\n",Offset);
				break;
			}
		}
		FreeLibrary(hCsrsrv);
		return Offset;
	}
	else
	{
		printf("[-]Load csrsrv.dll Failed\n");
		return 0;
	}
}

//����һ�����������б�
VOID CollectProcessNameInfo()	
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapShot=NULL;
	PPROC_NAME_INFO Tmp;
	ZeroMemory(&pe32,sizeof(PROCESSENTRY32));
	pe32.dwSize=sizeof(PROCESSENTRY32);
	//��һ�α���,��ȡ������
	hSnapShot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if (hSnapShot==INVALID_HANDLE_VALUE)
	{
		printf("Create Process SnapShot Failed!\n");
		return ;
	}
	if (Process32First(hSnapShot,&pe32))
	{
		do 
		{
			ProcessNameCnt++;
		} while(Process32Next(hSnapShot,&pe32));
	}
	CloseHandle(hSnapShot);
	ProcessNameInfo=(PPROC_NAME_INFO)VirtualAlloc(NULL,
		ProcessNameCnt*sizeof(PROC_NAME_INFO),
		MEM_COMMIT,
		PAGE_READWRITE
		);
	if (!ProcessNameInfo)
	{
		printf("Alloc Buffer For ProcesNameInfo Failed!\n");
		return ;
	}
	ZeroMemory(ProcessNameInfo,ProcessNameCnt*sizeof(PROC_NAME_INFO));
	Tmp=ProcessNameInfo;
	//�ڶ��α���,��ʼ�ռ�������Ϣ
	hSnapShot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if (hSnapShot==INVALID_HANDLE_VALUE)
	{
		printf("Create Process SnapShot Failed!\n");
		return ;
	}
	if (Process32First(hSnapShot,&pe32))
	{
		ProcessNameCnt=0;
		do 
		{
			Tmp[ProcessNameCnt].ProcessId=pe32.th32ProcessID;
			strncpy(Tmp[ProcessNameCnt].ImageName,pe32.szExeFile,IMAGEFILENAMELEN-1);
			ProcessNameCnt++;
		} while(Process32Next(hSnapShot,&pe32));
	}
	CloseHandle(hSnapShot);
	printf("[*]Get %d Processes NameInfo\n",ProcessNameCnt);
}

char *GetProcessNameByPid(ULONG pid)
{
	char *NameInfo=NULL;
	for (ULONG i=0;i<ProcessNameCnt;i++)
	{
		if (ProcessNameInfo[i].ProcessId==pid)
		{
			NameInfo=ProcessNameInfo[i].ImageName;
			break;
		}
	}
	return NameInfo;
}