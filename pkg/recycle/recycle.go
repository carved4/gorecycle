package recycle


import (
	"fmt"
	"unsafe"
	"strings"
	"time"
	"github.com/carved4/gorecycle/pkg/syscall"
	"github.com/carved4/gorecycle/pkg/types"
)

const (
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE           = 0x10
	SECTION_ALL_ACCESS     = 0x10000000
	SEC_COMMIT             = 0x8000000
	PROCESS_ALL_ACCESS     = 0x001F0FFF
	THREAD_ALL_ACCESS      = 0x001F03FF
	CREATE_SUSPENDED       = 0x00000004
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
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

func FindNtdll() uintptr {
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

func GetSyscall(apiName string, sys *types.Syscall) bool {
	ntdllBase := FindNtdll()
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
		// relative jump (0xe9), most common hook pattern
		if stubBytes[i] == 0xe9 {
			hooked = true
			break
		}
		// short jump (0xeb)
		if stubBytes[i] == 0xeb {
			hooked = true
			break
		}
		// absolute jump patterns (0xff /4 or /5)
		if stubBytes[i] == 0xff && i+1 < SYS_STUB_SIZE {
			// check for jmp [mem] (0xff 25) or jmp reg (0xff e0-e7, 0xff 20-27)
			nextByte := stubBytes[i+1]
			if nextByte == 0x25 || // jmp [rip+disp32]
				(nextByte >= 0xe0 && nextByte <= 0xe7) || // jmp reg
				(nextByte >= 0x20 && nextByte <= 0x27) {   // jmp [reg]
				hooked = true
				break
			}
		}
		// push + ret pattern (0x48 0xb8 ... 0xc3 or 0x68 ... 0xc3)
		if stubBytes[i] == 0x48 && i+9 < SYS_STUB_SIZE && stubBytes[i+1] == 0xb8 {
			// mov rax, imm64; jmp rax or similar patterns
			for j := i + 2; j < i + 10 && j < SYS_STUB_SIZE; j++ {
				if stubBytes[j] == 0xff && j+1 < SYS_STUB_SIZE && stubBytes[j+1] == 0xe0 {
					hooked = true
					break
				}
			}
			if hooked {
				break
			}
		}
		// push immediate + ret (0x68 ... 0xc3)
		if stubBytes[i] == 0x68 && i+5 < SYS_STUB_SIZE {
			// look for ret within next few bytes
			for j := i + 5; j < i + 8 && j < SYS_STUB_SIZE; j++ {
				if stubBytes[j] == 0xc3 {
					hooked = true
					break
				}
			}
			if hooked {
				break
			}
		}
		// int3/breakpoint (0xcc) debugger hooks
		if stubBytes[i] == 0xcc {
			hooked = true
			break
		}
		// multiple NOPs (0x90) potential nop sled indicating patching
		if stubBytes[i] == 0x90 && i+2 < SYS_STUB_SIZE && 
		   stubBytes[i+1] == 0x90 && stubBytes[i+2] == 0x90 {
			hooked = true
			break
		}
		// early return indicates stub was patched
		if stubBytes[i] == 0xc3 {
			return false
		}

		// look for clean syscall pattern
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
		// search both directions for clean syscall stubs to recycle
		for offset := 1; offset <= numFunctions; offset++ {
			downAddr := stub + uintptr(offset*DOWN)
			upAddr := stub + uintptr(offset*UP)
			
			// check down direction (higher addresses)
			if downAddr >= ntdllBase && downAddr < ntdllBase+0x100000 {
				downBytes := (*[SYS_STUB_SIZE]byte)(unsafe.Pointer(downAddr))
				
				// verify this is a clean stub
				isCleanDown := true
				for k := 0; k < SYS_STUB_SIZE && k < 16; k++ {
					// ceck for hook patterns in potential clean stub
					if downBytes[k] == 0xe9 || downBytes[k] == 0xeb || downBytes[k] == 0xcc ||
					   (downBytes[k] == 0xff && k+1 < SYS_STUB_SIZE && 
					    (downBytes[k+1] == 0x25 || 
					     (downBytes[k+1] >= 0xe0 && downBytes[k+1] <= 0xe7) ||
					     (downBytes[k+1] >= 0x20 && downBytes[k+1] <= 0x27))) {
						isCleanDown = false
						break
					}
					// check for nop sled
					if k+2 < SYS_STUB_SIZE && downBytes[k] == 0x90 && 
					   downBytes[k+1] == 0x90 && downBytes[k+2] == 0x90 {
						isCleanDown = false
						break
					}
				}
				
				// if clean look for syscall pattern
				if isCleanDown {
					for k := 0; k < SYS_STUB_SIZE-7; k++ {
						if downBytes[k] == 0x4c && downBytes[k+1] == 0x8b && downBytes[k+2] == 0xd1 &&
							downBytes[k+3] == 0xb8 && downBytes[k+6] == 0x00 && downBytes[k+7] == 0x00 {
							high := downBytes[k+5]
							low := downBytes[k+4]
							syscallNr = uint16(high)<<8|uint16(low) - uint16(offset)
							gateStub = downAddr
							found = true
							break
						}
					}
				}
				if found {
					break
				}
			}
			
			// check up direction (lower addresses)
			if upAddr >= ntdllBase && upAddr < ntdllBase+0x100000 {
				upBytes := (*[SYS_STUB_SIZE]byte)(unsafe.Pointer(upAddr))
				
				// verify this is a clean stub
				isCleanUp := true
				for k := 0; k < SYS_STUB_SIZE && k < 16; k++ {
					// check for hook patterns in potential clean stub
					if upBytes[k] == 0xe9 || upBytes[k] == 0xeb || upBytes[k] == 0xcc ||
					   (upBytes[k] == 0xff && k+1 < SYS_STUB_SIZE && 
					    (upBytes[k+1] == 0x25 || 
					     (upBytes[k+1] >= 0xe0 && upBytes[k+1] <= 0xe7) ||
					     (upBytes[k+1] >= 0x20 && upBytes[k+1] <= 0x27))) {
						isCleanUp = false
						break
					}
					// check for nop sled (not sure EDRs do this, i have been unable to test any of my stuff against a "hooked" environment)
					// beyond avast free, whom im not sure installs hooks
					if k+2 < SYS_STUB_SIZE && upBytes[k] == 0x90 && 
					   upBytes[k+1] == 0x90 && upBytes[k+2] == 0x90 {
						isCleanUp = false
						break
					}
				}
				
				// if clean we look for syscall pattern
				if isCleanUp {
					for k := 0; k < SYS_STUB_SIZE-7; k++ {
						if upBytes[k] == 0x4c && upBytes[k+1] == 0x8b && upBytes[k+2] == 0xd1 &&
							upBytes[k+3] == 0xb8 && upBytes[k+6] == 0x00 && upBytes[k+7] == 0x00 {
							high := upBytes[k+5]
							low := upBytes[k+4]
							syscallNr = uint16(high)<<8|uint16(low) + uint16(offset)
							gateStub = upAddr
							found = true
							break
						}
					}
				}
				if found {
					break
				}
			}
		}
		if !found {
			fmt.Println("[-] unable to find clean syscall gate using RecycleGate method")
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

	sys.Nr = syscallNr
	sys.Gate = gate

	return true
}