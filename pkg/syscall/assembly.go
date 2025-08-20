package syscall

import (
    "errors"
    "unsafe"
)

//go:noescape
func do_syscall_indirect(ssn uint16, trampoline uintptr, argh ...uintptr) uint32

//go:noescape
func getTrampoline(stubAddr uintptr) uintptr

//go:noescape
func GetPEB() uintptr

//nosplit
//noinline
func WalkLDR(ldrPtr uintptr) uintptr

//nosplit
//noinline
func GetNextModule(currentModule uintptr) uintptr

//nosplit
//noinline
func ReadModuleBase(modulePtr uintptr) uintptr

//nosplit
//noinline
func ReadModuleTimestamp(modulePtr uintptr) uint32

//nosplit
//noinline
func ReadModuleName(modulePtr uintptr) (length uint16, buffer uintptr)


func IndirectSyscall(syscallNum uint16, syscallAddr uintptr, args ...uintptr) (uintptr, error) {
    // Fast-path: if caller already provides address of `syscall;ret`, use it directly.
    trampoline := syscallAddr
    if !looksLikeGate(syscallAddr) {
        trampoline = getTrampoline(syscallAddr)
        if trampoline == 0 {
            return 0, errors.New("trampoline is null")
        }
    }
    result := do_syscall_indirect(syscallNum, trampoline, args...)
    return uintptr(result), nil
}

// looksLikeGate checks for 0f 05 c3 at the given address.
func looksLikeGate(addr uintptr) bool {
    if addr == 0 {
        return false
    }
    b := (*[3]byte)(unsafe.Pointer(addr))
    return b[0] == 0x0f && b[1] == 0x05 && b[2] == 0xc3
}

