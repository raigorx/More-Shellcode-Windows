#pragma once
// Structures extracted from
// https://github.com/mrexodia/phnt-single-header
#include <windows.h>

#define RTL_MAX_DRIVE_LETTERS 32

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];

typedef struct _LEAP_SECOND_DATA *PLEAP_SECOND_DATA;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY {
  ULONG Flags;
  UNICODE_STRING DosPath;
  HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

#define ASSEMBLY_STORAGE_MAP_ASSEMBLY_ARRAY_IS_HEAP_ALLOCATED 0x00000001

typedef struct _ASSEMBLY_STORAGE_MAP {
  ULONG Flags;
  ULONG AssemblyCount;
  PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _ACTIVATION_CONTEXT_DATA {
  ULONG Magic;
  ULONG HeaderSize;
  ULONG FormatVersion;
  ULONG TotalSize;
  ULONG DefaultTocOffset;   //  to ACTIVATION_CONTEXT_DATA_TOC_HEADER
  ULONG ExtendedTocOffset;  //  to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
  ULONG
  AssemblyRosterOffset;  //  to
                         //  ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
  ULONG Flags;           //  ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _KSYSTEM_TIME {
  ULONG LowPart;
  LONG High1Time;
  LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE {
  NtProductWinNt = 1,
  NtProductLanManNt,
  NtProductServer
} NT_PRODUCT_TYPE,
    *PNT_PRODUCT_TYPE;

typedef struct _SILO_USER_SHARED_DATA {
  ULONG ServiceSessionId;
  ULONG ActiveConsoleId;
  LONGLONG ConsoleSessionForegroundProcessId;
  NT_PRODUCT_TYPE NtProductType;
  ULONG SuiteMask;
  ULONG SharedUserSessionId;  //  since RS2
  BOOLEAN IsMultiSessionSku;
  WCHAR NtSystemRoot[260];
  USHORT UserModeGlobalLogger[16];
  ULONG TimeZoneId;  //  since 21H2
  LONG TimeZoneBiasStamp;
  KSYSTEM_TIME TimeZoneBias;
  LARGE_INTEGER TimeZoneBiasEffectiveStart;
  LARGE_INTEGER TimeZoneBiasEffectiveEnd;
} SILO_USER_SHARED_DATA, *PSILO_USER_SHARED_DATA;

typedef struct _API_SET_NAMESPACE {
  ULONG Version;
  ULONG Size;
  ULONG Flags;
  ULONG Count;
  ULONG EntryOffset;
  ULONG HashOffset;
  ULONG HashFactor;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;

typedef struct _STRING {
  USHORT Length;
  USHORT MaximumLength;
  _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, *PSTRING, ANSI_STRING, *PANSI_STRING, OEM_STRING, *POEM_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT Flags;
  USHORT Length;
  ULONG TimeStamp;
  STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
  UNICODE_STRING DosPath;
  HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _STRING32 {
  USHORT Length;
  USHORT MaximumLength;
  ULONG Buffer;
} STRING32, *PSTRING32;

typedef struct _RTL_DRIVE_LETTER_CURDIR32 {
  USHORT Flags;
  USHORT Length;
  ULONG TimeStamp;
  STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, *PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG MaximumLength;
  ULONG Length;

  ULONG Flags;
  ULONG DebugFlags;

  HANDLE ConsoleHandle;
  ULONG ConsoleFlags;
  HANDLE StandardInput;
  HANDLE StandardOutput;
  HANDLE StandardError;

  CURDIR CurrentDirectory;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
  PVOID Environment;

  ULONG StartingX;
  ULONG StartingY;
  ULONG CountX;
  ULONG CountY;
  ULONG CountCharsX;
  ULONG CountCharsY;
  ULONG FillAttribute;

  ULONG WindowFlags;
  ULONG ShowWindowFlags;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING DesktopInfo;
  UNICODE_STRING ShellInfo;
  UNICODE_STRING RuntimeData;
  RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

  ULONG_PTR EnvironmentSize;
  ULONG_PTR EnvironmentVersion;

  PVOID PackageDependencyData;
  ULONG ProcessGroupId;
  ULONG LoaderThreads;

  UNICODE_STRING RedirectionDllName;  //  REDSTONE4
  UNICODE_STRING HeapPartitionName;   //  19H1
  ULONG_PTR DefaultThreadpoolCpuSetMasks;
  ULONG DefaultThreadpoolCpuSetMaskCount;
  ULONG DefaultThreadpoolThreadMaximum;
  ULONG HeapMemoryTypeMask;  //  WIN11
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  HANDLE SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
  BOOLEAN ShutdownInProgress;
  HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;

  union {
    BOOLEAN BitField;

    struct {
      BOOLEAN ImageUsesLargePages : 1;
      BOOLEAN IsProtectedProcess : 1;
      BOOLEAN IsImageDynamicallyRelocated : 1;
      BOOLEAN SkipPatchingUser32Forwarders : 1;
      BOOLEAN IsPackagedProcess : 1;
      BOOLEAN IsAppContainer : 1;
      BOOLEAN IsProtectedProcessLight : 1;
      BOOLEAN IsLongPathAwareProcess : 1;
    };
  };

  HANDLE Mutant;

  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PRTL_CRITICAL_SECTION FastPebLock;
  PSLIST_HEADER AtlThunkSListPtr;
  PVOID IFEOKey;

  union {
    ULONG CrossProcessFlags;

    struct {
      ULONG ProcessInJob : 1;
      ULONG ProcessInitializing : 1;
      ULONG ProcessUsingVEH : 1;
      ULONG ProcessUsingVCH : 1;
      ULONG ProcessUsingFTH : 1;
      ULONG ProcessPreviouslyThrottled : 1;
      ULONG ProcessCurrentlyThrottled : 1;
      ULONG ProcessImagesHotPatched : 1;  //  REDSTONE5
      ULONG ReservedBits0 : 24;
    };
  };

  union {
    PVOID KernelCallbackTable;
    PVOID UserSharedInfoPtr;
  };

  ULONG SystemReserved;
  ULONG AtlThunkSListPtr32;
  PAPI_SET_NAMESPACE ApiSetMap;
  ULONG TlsExpansionCounter;
  PVOID TlsBitmap;
  ULONG TlsBitmapBits[2];

  PVOID ReadOnlySharedMemoryBase;
  PSILO_USER_SHARED_DATA SharedData;  //  HotpatchInformation
  PVOID *ReadOnlyStaticServerData;

  PVOID AnsiCodePageData;      //  PCPTABLEINFO
  PVOID OemCodePageData;       //  PCPTABLEINFO
  PVOID UnicodeCaseTableData;  //  PNLSTABLEINFO

  ULONG NumberOfProcessors;
  ULONG NtGlobalFlag;

  ULARGE_INTEGER CriticalSectionTimeout;
  SIZE_T HeapSegmentReserve;
  SIZE_T HeapSegmentCommit;
  SIZE_T HeapDeCommitTotalFreeThreshold;
  SIZE_T HeapDeCommitFreeBlockThreshold;

  ULONG NumberOfHeaps;
  ULONG MaximumNumberOfHeaps;
  PVOID *ProcessHeaps;  //  PHEAP

  PVOID GdiSharedHandleTable;  //  PGDI_SHARED_MEMORY
  PVOID ProcessStarterHelper;
  ULONG GdiDCAttributeList;

  PRTL_CRITICAL_SECTION LoaderLock;

  ULONG OSMajorVersion;
  ULONG OSMinorVersion;
  USHORT OSBuildNumber;
  USHORT OSCSDVersion;
  ULONG OSPlatformId;
  ULONG ImageSubsystem;
  ULONG ImageSubsystemMajorVersion;
  ULONG ImageSubsystemMinorVersion;
  KAFFINITY ActiveProcessAffinityMask;
  GDI_HANDLE_BUFFER GdiHandleBuffer;
  PVOID PostProcessInitRoutine;

  PVOID TlsExpansionBitmap;
  ULONG TlsExpansionBitmapBits[32];

  ULONG SessionId;

  ULARGE_INTEGER AppCompatFlags;
  ULARGE_INTEGER AppCompatFlagsUser;
  PVOID pShimData;
  PVOID AppCompatInfo;  //  APPCOMPAT_EXE_DATA

  UNICODE_STRING CSDVersion;

  PACTIVATION_CONTEXT_DATA ActivationContextData;
  PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
  PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
  PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

  SIZE_T MinimumStackCommit;

  PVOID SparePointers[2];  //  19H1 (previously FlsCallback to FlsHighIndex)
  PVOID PatchLoaderData;
  PVOID ChpeV2ProcessInfo;  //  _CHPEV2_PROCESS_INFO

  ULONG AppModelFeatureState;
  ULONG SpareUlongs[2];

  USHORT ActiveCodePage;
  USHORT OemCodePage;
  USHORT UseCaseMapping;
  USHORT UnusedNlsField;

  PVOID WerRegistrationData;
  PVOID WerShipAssertPtr;

  union {
    PVOID pContextData;  //  WIN7
    PVOID pUnused;       //  WIN10
    PVOID EcCodeBitMap;  //  WIN11
  };

  PVOID pImageHeaderHash;

  union {
    ULONG TracingFlags;

    struct {
      ULONG HeapTracingEnabled : 1;
      ULONG CritSecTracingEnabled : 1;
      ULONG LibLoaderTracingEnabled : 1;
      ULONG SpareTracingBits : 29;
    };
  };

  ULONGLONG CsrServerReadOnlySharedMemoryBase;
  PRTL_CRITICAL_SECTION TppWorkerpListLock;
  LIST_ENTRY TppWorkerpList;
  PVOID WaitOnAddressHashTable[128];
  PVOID TelemetryCoverageHeader;  //  REDSTONE3
  ULONG CloudFileFlags;
  ULONG CloudFileDiagFlags;  //  REDSTONE4
  CHAR PlaceholderCompatibilityMode;
  CHAR PlaceholderCompatibilityModeReserved[7];
  PLEAP_SECOND_DATA LeapSecondData;  //  REDSTONE5

  union {
    ULONG LeapSecondFlags;

    struct {
      ULONG SixtySecondEnabled : 1;
      ULONG Reserved : 31;
    };
  };

  ULONG NtGlobalFlag2;
  ULONGLONG ExtendedFeatureDisableMask;  //  since WIN11
} PEB, *PPEB;

typedef BOOLEAN(NTAPI *PLDR_INIT_ROUTINE)(_In_ PVOID DllHandle,
                                          _In_ ULONG Reason,
                                          _In_opt_ PVOID Context);

typedef struct _ACTIVATION_CONTEXT *PACTIVATION_CONTEXT;

typedef struct _LDR_SERVICE_TAG_RECORD {
  struct _LDR_SERVICE_TAG_RECORD *Next;
  ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST {
  PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE {
  LdrModulesMerged = -5,
  LdrModulesInitError = -4,
  LdrModulesSnapError = -3,
  LdrModulesUnloaded = -2,
  LdrModulesUnloading = -1,
  LdrModulesPlaceHolder = 0,
  LdrModulesMapping = 1,
  LdrModulesMapped = 2,
  LdrModulesWaitingForDependencies = 3,
  LdrModulesSnapping = 4,
  LdrModulesSnapped = 5,
  LdrModulesCondensed = 6,
  LdrModulesReadyToInit = 7,
  LdrModulesInitializing = 8,
  LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE {
  LIST_ENTRY Modules;
  PLDR_SERVICE_TAG_RECORD ServiceTagList;
  ULONG LoadCount;
  ULONG LoadWhileUnloadingCount;
  ULONG LowestLink;

  union {
    LDRP_CSLIST Dependencies;
    SINGLE_LIST_ENTRY RemovalLink;
  };

  LDRP_CSLIST IncomingDependencies;
  LDR_DDAG_STATE State;
  SINGLE_LIST_ENTRY CondenseLink;
  ULONG PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

typedef struct _LDRP_LOAD_CONTEXT *PLDRP_LOAD_CONTEXT;

typedef struct _RTL_BALANCED_NODE {
  union {
    struct _RTL_BALANCED_NODE *Children[2];

    struct {
      struct _RTL_BALANCED_NODE *Left;
      struct _RTL_BALANCED_NODE *Right;
    };
  };

  union {
    UCHAR Red : 1;
    UCHAR Balance : 2;
    ULONG_PTR ParentValue;
  };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef enum _LDR_DLL_LOAD_REASON {
  LoadReasonStaticDependency,
  LoadReasonStaticForwarderDependency,
  LoadReasonDynamicForwarderDependency,
  LoadReasonDelayloadDependency,
  LoadReasonDynamicLoad,
  LoadReasonAsImageLoad,
  LoadReasonAsDataLoad,
  LoadReasonEnclavePrimary,  //  since REDSTONE3
  LoadReasonEnclaveDependency,
  LoadReasonPatchImage,  //  since WIN11
  LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON,
    *PLDR_DLL_LOAD_REASON;

typedef enum _LDR_HOT_PATCH_STATE {
  LdrHotPatchBaseImage,
  LdrHotPatchNotApplied,
  LdrHotPatchAppliedReverse,
  LdrHotPatchAppliedForward,
  LdrHotPatchFailedToPatch,
  LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE,
    *PLDR_HOT_PATCH_STATE;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;

  union {
    LIST_ENTRY InInitializationOrderLinks;
    LIST_ENTRY InProgressLinks;
  };

  PVOID DllBase;
  PLDR_INIT_ROUTINE EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;

  union {
    UCHAR FlagGroup[4];
    ULONG Flags;

    struct {
      ULONG PackagedBinary : 1;
      ULONG MarkedForRemoval : 1;
      ULONG ImageDll : 1;
      ULONG LoadNotificationsSent : 1;
      ULONG TelemetryEntryProcessed : 1;
      ULONG ProcessStaticImport : 1;
      ULONG InLegacyLists : 1;
      ULONG InIndexes : 1;
      ULONG ShimDll : 1;
      ULONG InExceptionTable : 1;
      ULONG ReservedFlags1 : 2;
      ULONG LoadInProgress : 1;
      ULONG LoadConfigProcessed : 1;
      ULONG EntryProcessed : 1;
      ULONG ProtectDelayLoad : 1;
      ULONG ReservedFlags3 : 2;
      ULONG DontCallForThreads : 1;
      ULONG ProcessAttachCalled : 1;
      ULONG ProcessAttachFailed : 1;
      ULONG CorDeferredValidate : 1;
      ULONG CorImage : 1;
      ULONG DontRelocate : 1;
      ULONG CorILOnly : 1;
      ULONG ChpeImage : 1;
      ULONG ChpeEmulatorImage : 1;
      ULONG ReservedFlags5 : 1;
      ULONG Redirected : 1;
      ULONG ReservedFlags6 : 2;
      ULONG CompatDatabaseProcessed : 1;
    };
  };

  USHORT ObsoleteLoadCount;
  USHORT TlsIndex;
  LIST_ENTRY HashLinks;
  ULONG TimeDateStamp;
  PACTIVATION_CONTEXT EntryPointActivationContext;
  PVOID Lock;  //  RtlAcquireSRWLockExclusive
  PLDR_DDAG_NODE DdagNode;
  LIST_ENTRY NodeModuleLink;
  PLDRP_LOAD_CONTEXT LoadContext;
  PVOID ParentDllBase;
  PVOID SwitchBackContext;
  RTL_BALANCED_NODE BaseAddressIndexNode;
  RTL_BALANCED_NODE MappingInfoIndexNode;
  ULONG_PTR OriginalBase;
  LARGE_INTEGER LoadTime;
  ULONG BaseNameHashValue;
  LDR_DLL_LOAD_REASON LoadReason;  //  since WIN8
  ULONG ImplicitPathOptions;
  ULONG ReferenceCount;  //  since WIN10
  ULONG DependentLoadFlags;
  UCHAR SigningLevel;  //  since REDSTONE2
  ULONG CheckSum;      //  since 22H1
  PVOID ActivePatchImageBase;
  LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;