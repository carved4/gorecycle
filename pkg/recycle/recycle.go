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
    return Default().Find(apiName, sys)
}
