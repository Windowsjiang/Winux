typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _CSR_NT_SESSION
{
    ULONG ReferenceCount;
    LIST_ENTRY SessionList;
    ULONG SessionId;
} CSR_NT_SESSION, *PCSR_NT_SESSION;

typedef struct _CSR_PROCESS
{
    CLIENT_ID ClientId;
    LIST_ENTRY ListLink;
    LIST_ENTRY ThreadList;
    struct _CSR_PROCESS *Parent;
    PCSR_NT_SESSION NtSession;
    ULONG ExpectedVersion;
    HANDLE ClientPort;
    ULONG_PTR ClientViewBase;
    ULONG_PTR ClientViewBounds;
    HANDLE ProcessHandle;
    ULONG SequenceNumber;
    ULONG Flags;
    ULONG DebugFlags;
    CLIENT_ID DebugCid;
    ULONG ReferenceCount;
    ULONG ProcessGroupId;
    ULONG ProcessGroupSequence;
    ULONG fVDM;
    ULONG ThreadCount;
    ULONG PriorityClass;
    ULONG Reserved;
    ULONG ShutdownLevel;
    ULONG ShutdownFlags;
    //PVOID ServerData[];
} CSR_PROCESS, *PCSR_PROCESS;

typedef struct _CSR_THREAD
{
    LARGE_INTEGER CreateTime;
    LIST_ENTRY Link;
    LIST_ENTRY HashLinks;
    CLIENT_ID ClientId;
    PCSR_PROCESS Process;
    PVOID WaitBlock; //struct _CSR_WAIT_BLOCK *WaitBlock;
    HANDLE ThreadHandle;
    ULONG Flags;
    ULONG ReferenceCount;
    ULONG ImpersonationCount;
} CSR_THREAD, *PCSR_THREAD;

/* ENUMERATIONS **************************************************************/
#define CSR_SRV_SERVER 0

typedef enum _CSR_PROCESS_FLAGS
{
    CsrProcessTerminating = 0x1,
    CsrProcessSkipShutdown = 0x2,
    CsrProcessCreateNewGroup = 0x100,
    CsrProcessTerminated = 0x200,
    CsrProcessLastThreadTerminated = 0x400,
    CsrProcessIsConsoleApp = 0x800
} CSR_PROCESS_FLAGS, *PCSR_PROCESS_FLAGS;

typedef enum _CSR_THREAD_FLAGS
{
    CsrThreadAltertable = 0x1,
    CsrThreadInTermination = 0x2,
    CsrThreadTerminated = 0x4,
    CsrThreadIsServerThread = 0x10
} CSR_THREAD_FLAGS, *PCSR_THREAD_FLAGS;

typedef enum _SHUTDOWN_RESULT
{
    CsrShutdownCsrProcess = 1,
    CsrShutdownNonCsrProcess,
    CsrShutdownCancelled
} SHUTDOWN_RESULT, *PSHUTDOWN_RESULT;

typedef enum _CSR_SHUTDOWN_FLAGS
{
    CsrShutdownSystem = 4,
    CsrShutdownOther = 8
} CSR_SHUTDOWN_FLAGS, *PCSR_SHUTDOWN_FLAGS;

typedef enum _CSR_DEBUG_FLAGS
{
    CsrDebugOnlyThisProcess = 1,
    CsrDebugProcessChildren = 2
} CSR_PROCESS_DEBUG_FLAGS, *PCSR_PROCESS_DEBUG_FLAGS;