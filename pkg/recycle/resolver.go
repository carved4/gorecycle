package recycle

import (
    "fmt"
    "strings"
    "sync"
    "unsafe"
    "github.com/carved4/gorecycle/pkg/types"
)

// Resolver caches ntdll export table lookups to avoid repeated parsing.
type Resolver struct {
    base         uintptr
    exportDir    *types.ImageExportDirectory
    addrFuncs    *[65536]uint32
    addrNames    *[65536]uint32
    addrOrdinals *[65536]uint16
    numNames     uint32
    initErr      error
}

var (
    defaultOnce sync.Once
    defaultRes  *Resolver
)

// Default returns a process-wide cached resolver instance.
func Default() *Resolver {
    defaultOnce.Do(func() {
        r := &Resolver{}
        if err := r.init(); err != nil {
            // store error but keep instance to avoid panics; calls will fail gracefully
            r.initErr = err
        }
        defaultRes = r
    })
    return defaultRes
}

func (r *Resolver) init() error {
    base := FindNtdll()
    if base == 0 {
        return fmt.Errorf("ntdll base is null")
    }

    dos := (*types.ImageDosHeader)(unsafe.Pointer(base))
    if dos == nil || dos.Signature != 0x5A4D {
        return fmt.Errorf("invalid DOS header")
    }

    nth := (*types.ImageNtHeaders)(unsafe.Pointer(base + uintptr(dos.ElfanewOffset)))
    if nth == nil || nth.Signature != 0x00004550 {
        return fmt.Errorf("invalid NT headers")
    }

    if len(nth.OptionalHeader.DataDirectory) == 0 {
        return fmt.Errorf("no data directories")
    }

    exportRVA := nth.OptionalHeader.DataDirectory[0].VirtualAddress
    if exportRVA == 0 {
        return fmt.Errorf("export directory RVA is 0")
    }

    exp := (*types.ImageExportDirectory)(unsafe.Pointer(base + uintptr(exportRVA)))
    if exp == nil {
        return fmt.Errorf("export directory is null")
    }

    r.base = base
    r.exportDir = exp
    r.addrFuncs = (*[65536]uint32)(unsafe.Pointer(base + uintptr(exp.AddressOfFunctions)))
    r.addrNames = (*[65536]uint32)(unsafe.Pointer(base + uintptr(exp.AddressOfNames)))
    r.addrOrdinals = (*[65536]uint16)(unsafe.Pointer(base + uintptr(exp.AddressOfNameOrdinals)))
    r.numNames = exp.NumberOfNames
    return nil
}

// Find returns the syscall number and clean gate for the given Nt*/Zw* export name.
// It mirrors GetSyscall behavior but uses cached tables.
func (r *Resolver) Find(apiName string, out *types.Syscall) bool {
    if r == nil || r.initErr != nil || r.base == 0 || r.exportDir == nil {
        fmt.Println("[-] resolver not initialized")
        return false
    }

    var stub uintptr
    for i := uint32(0); i < r.numNames; i++ {
        nameRva := r.addrNames[i]
        namePtr := (*[256]byte)(unsafe.Pointer(r.base + uintptr(nameRva)))
        // build name until NUL
        var name string
        for j := 0; j < 256; j++ {
            if namePtr[j] == 0 {
                break
            }
            name += string(namePtr[j])
        }
        if name == apiName {
            ord := r.addrOrdinals[i]
            funcRva := r.addrFuncs[ord]
            stub = r.base + uintptr(funcRva)
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
    // parse stub to detect hooks and try to extract SSN when clean
    for i := 0; i < SYS_STUB_SIZE; i++ {
        b := stubBytes[i]
        // common hook patterns
        if b == 0xe9 || b == 0xeb || b == 0xcc { // jmp rel32/8, int3
            hooked = true
            break
        }
        if b == 0xff && i+1 < SYS_STUB_SIZE { // absolute jmp variants
            nb := stubBytes[i+1]
            if nb == 0x25 || (nb >= 0xe0 && nb <= 0xe7) || (nb >= 0x20 && nb <= 0x27) {
                hooked = true
                break
            }
        }
        // push imm + ret -> trampoline style
        if b == 0x68 && i+5 < SYS_STUB_SIZE {
            for j := i + 5; j < i+8 && j < SYS_STUB_SIZE; j++ {
                if stubBytes[j] == 0xc3 {
                    hooked = true
                    break
                }
            }
            if hooked {
                break
            }
        }
        // suspicious nop sled
        if b == 0x90 && i+2 < SYS_STUB_SIZE && stubBytes[i+1] == 0x90 && stubBytes[i+2] == 0x90 {
            hooked = true
            break
        }
        // early ret -> patched
        if b == 0xc3 {
            return false
        }
        // clean sequence: mov r10, rcx; mov eax, imm16; syscall; ret
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

    // If hooked, recycle a neighboring clean syscall gate and derive SSN by offset
    if hooked {
        numFuncs := int(r.exportDir.NumberOfFunctions)
        found := false
        for offset := 1; offset <= numFuncs; offset++ {
            // scan downwards (higher addresses)
            downAddr := stub + uintptr(offset*DOWN)
            if downAddr >= r.base && downAddr < r.base+0x100000 {
                downBytes := (*[SYS_STUB_SIZE]byte)(unsafe.Pointer(downAddr))
                if isCleanStub(downBytes) {
                    if nr, ok := extractSSN(downBytes); ok {
                        syscallNr = nr - uint16(offset)
                        gateStub = downAddr
                        found = true
                        break
                    }
                }
            }
            // scan upwards (lower addresses)
            upAddr := stub + uintptr(offset*UP)
            if upAddr >= r.base && upAddr < r.base+0x100000 {
                upBytes := (*[SYS_STUB_SIZE]byte)(unsafe.Pointer(upAddr))
                if isCleanStub(upBytes) {
                    if nr, ok := extractSSN(upBytes); ok {
                        syscallNr = nr + uint16(offset)
                        gateStub = upAddr
                        found = true
                        break
                    }
                }
            }
        }
        if !found {
            fmt.Println("[-] unable to find clean syscall gate using RecycleGate method")
            return false
        }
    }

    // locate 0f 05 c3 within gateStub
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

    out.Nr = syscallNr
    out.Gate = gate
    return true
}

// isCleanStub performs light-weight hook heuristics for a candidate stub.
func isCleanStub(b *[SYS_STUB_SIZE]byte) bool {
    for i := 0; i < SYS_STUB_SIZE && i < 16; i++ {
        if b[i] == 0xe9 || b[i] == 0xeb || b[i] == 0xcc {
            return false
        }
        if b[i] == 0xff && i+1 < SYS_STUB_SIZE {
            nb := b[i+1]
            if nb == 0x25 || (nb >= 0xe0 && nb <= 0xe7) || (nb >= 0x20 && nb <= 0x27) {
                return false
            }
        }
        if i+2 < SYS_STUB_SIZE && b[i] == 0x90 && b[i+1] == 0x90 && b[i+2] == 0x90 {
            return false
        }
    }
    return true
}

// extractSSN finds the imm16 loaded into eax in a clean stub.
func extractSSN(b *[SYS_STUB_SIZE]byte) (uint16, bool) {
    for i := 0; i < SYS_STUB_SIZE-7; i++ {
        if b[i] == 0x4c && b[i+1] == 0x8b && b[i+2] == 0xd1 && b[i+3] == 0xb8 && b[i+6] == 0x00 && b[i+7] == 0x00 {
            hi := b[i+5]
            lo := b[i+4]
            return uint16(hi)<<8 | uint16(lo), true
        }
    }
    return 0, false
}

// Helper used by dump to derive display name without allocations.
func isZwName(name string) bool { return strings.HasPrefix(name, "Zw") }

