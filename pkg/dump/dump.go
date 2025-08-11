package dump

import (
	"fmt"
	"unsafe"
	"strings"
	rc "gorecycle/pkg/recycle"
	"gorecycle/pkg/types"
)


func DumpAllSyscalls() {
	fmt.Println("[+] dumping all syscalls 0->947")

	ntdllBase := rc.FindNtdll()
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
		stubBytes := (*[rc.SYS_STUB_SIZE]byte)(unsafe.Pointer(stub))
		for k := 0; k < rc.SYS_STUB_SIZE-7; k++ {
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
