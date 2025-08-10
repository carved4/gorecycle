package types


type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type CURDIR struct {
	DosPath UNICODE_STRING
	Handle  uintptr
}

type RTL_DRIVE_LETTER_CURDIR struct {
	Flags     uint16
	Length    uint16
	TimeStamp uint32
	DosPath   UNICODE_STRING
}

type RTL_USER_PROCESS_PARAMETERS struct {
	MaximumLength     uint32
	Length            uint32
	Flags             uint32
	DebugFlags        uint32
	ConsoleHandle     uintptr
	ConsoleFlags      uint32
	StandardInput     uintptr
	StandardOutput    uintptr
	StandardError     uintptr
	CurrentDirectory  CURDIR
	DllPath           UNICODE_STRING
	ImagePathName     UNICODE_STRING
	CommandLine       UNICODE_STRING
	Environment       uintptr
	StartingX         uint32
	StartingY         uint32
	CountX            uint32
	CountY            uint32
	CountCharsX       uint32
	CountCharsY       uint32
	FillAttribute     uint32
	WindowFlags       uint32
	ShowWindowFlags   uint32
	WindowTitle       UNICODE_STRING
	DesktopInfo       UNICODE_STRING
	ShellInfo         UNICODE_STRING
	RuntimeData       UNICODE_STRING
	CurrentDirectories [32]RTL_DRIVE_LETTER_CURDIR
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uintptr
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  LIST_ENTRY
	TimeDateStamp              uint32
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint32
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

type PEB struct {
	InheritedAddressSpace      byte
	ReadImageFileExecOptions   byte
	BeingDebugged              byte
	BitField                   byte
	Mutant                     uintptr
	ImageBaseAddress           uintptr
	Ldr                        *PEB_LDR_DATA
	ProcessParameters          *RTL_USER_PROCESS_PARAMETERS
	SubSystemData              uintptr
	ProcessHeap                uintptr
	FastPebLock                uintptr
	AtlThunkSListPtr           uintptr
	IFEOKey                    uintptr
	CrossProcessFlags          uint32
	KernelCallbackTable        uintptr
	SystemReserved             uint32
	AtlThunkSListPtr32         uint32
	ApiSetMap                  uintptr
	TlsExpansionCounter        uint32
	TlsBitmap                  uintptr
	TlsBitmapBits              [2]uint32
	ReadOnlySharedMemoryBase   uintptr
	SharedData                 uintptr
	ReadOnlyStaticServerData   uintptr
	AnsiCodePageData           uintptr
	OemCodePageData            uintptr
	UnicodeCaseTableData       uintptr
	NumberOfProcessors         uint32
	NtGlobalFlag               uint32
	CriticalSectionTimeout     int64
	HeapSegmentReserve         uintptr
	HeapSegmentCommit          uintptr
	HeapDeCommitTotalFreeThreshold uintptr
	HeapDeCommitFreeBlockThreshold uintptr
	NumberOfHeaps              uint32
	MaximumNumberOfHeaps       uint32
	ProcessHeaps               uintptr
	GdiSharedHandleTable       uintptr
	ProcessStarterHelper       uintptr
	GdiDCAttributeList         uint32
	LoaderLock                 uintptr
	OSMajorVersion             uint32
	OSMinorVersion             uint32
	OSBuildNumber              uint16
	OSCSDVersion               uint16
	OSPlatformId               uint32
	ImageSubsystem             uint32
	ImageSubsystemMajorVersion uint32
	ImageSubsystemMinorVersion uint32
	ActiveProcessAffinityMask  uintptr
	GdiHandleBuffer            [60]uint32
	PostProcessInitRoutine     uintptr
	TlsExpansionBitmap         uintptr
	TlsExpansionBitmapBits     [32]uint32
	SessionId                  uint32
	AppCompatFlags             uint64
	AppCompatFlagsUser         uint64
	PShimData                  uintptr
	AppCompatInfo              uintptr
	CSDVersion                 UNICODE_STRING
	ActivationContextData      uintptr
	ProcessAssemblyStorageMap  uintptr
	SystemDefaultActivationContextData uintptr
	SystemAssemblyStorageMap   uintptr
	MinimumStackCommit         uintptr
	FlsCallback                uintptr
	FlsListHead                LIST_ENTRY
	FlsBitmap                  uintptr
	FlsBitmapBits              [4]uint32
	FlsHighIndex               uint32
	WerRegistrationData        uintptr
	WerShipAssertPtr           uintptr
	PUnused                    uintptr
	PImageHeaderHash           uintptr
	TracingFlags               uint32
	CsrServerReadOnlySharedMemoryBase uint64
	TppWorkerpListLock         uintptr
	TppWorkerpList             LIST_ENTRY
	WaitOnAddressHashTable     [128]uintptr
	TelemetryCoverageHeader    uintptr
	CloudFileFlags             uint32
	CloudFileDiagFlags         uint32
	PlaceholderCompatibilityMode byte
	PlaceholderCompatibilityModeReserved [7]byte
	LeapSecondData             uintptr
	LeapSecondFlags            uint32
	NtGlobalFlag2              uint32
}

type Syscall struct {
	SyscallNr    uint16
	RecycledGate uintptr
}

type StartupInfo struct {
	Cb              uint32
	_               *uint16
	Desktop         *uint16
	Title           *uint16
	X               uint32
	Y               uint32
	XSize           uint32
	YSize           uint32
	XCountChars     uint32
	YCountChars     uint32
	FillAttribute   uint32
	Flags           uint32
	ShowWindow      uint16
	_               uint16
	_               *byte
	StdInput        uintptr
	StdOutput       uintptr
	StdErr          uintptr
}

type ProcessInformation struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
}

type ImageDosHeader struct {
	Signature    uint16
	BytesOnLastPage uint16
	PagesInFile  uint16
	Relocations  uint16
	SizeOfHeader uint16
	MinExtraParagraphs uint16
	MaxExtraParagraphs uint16
	InitialSS    uint16
	InitialSP    uint16
	Checksum     uint16
	InitialIP    uint16
	InitialCS    uint16
	RelocTableOffset uint16
	OverlayNumber uint16
	Reserved     [4]uint16
	OEMIdentifier uint16
	OEMInformation uint16
	Reserved2    [10]uint16
	ElfanewOffset uint32
}

type ImageNtHeaders struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader
}

type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type ImageOptionalHeader struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]ImageDataDirectory
}

type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type ImageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}
