package dump

import (
    "fmt"
    "sort"
    "unsafe"
    "strings"
    rc "github.com/carved4/gorecycle/pkg/recycle"
    "github.com/carved4/gorecycle/pkg/types"
)


func DumpAllSyscalls() {
    fmt.Println("[+] dumping all syscalls (via cached resolver)")

    r := rc.Default()
    if r == nil {
        fmt.Println("[-] resolver is nil")
        return
    }
    base := rc.FindNtdll()
    if base == 0 {
        fmt.Println("[-] ntdll base is null")
        return
    }

    exportDir := (*types.ImageExportDirectory)(unsafe.Pointer(base + uintptr((*types.ImageNtHeaders)(unsafe.Pointer(base+uintptr((*types.ImageDosHeader)(unsafe.Pointer(base)).ElfanewOffset))).OptionalHeader.DataDirectory[0].VirtualAddress)))
    if exportDir == nil {
        fmt.Println("[-] export directory is null")
        return
    }

    names := (*[65536]uint32)(unsafe.Pointer(base + uintptr(exportDir.AddressOfNames)))
    ords := (*[65536]uint16)(unsafe.Pointer(base + uintptr(exportDir.AddressOfNameOrdinals)))
    funs := (*[65536]uint32)(unsafe.Pointer(base + uintptr(exportDir.AddressOfFunctions)))

    type row struct{ ssn uint16; addr uintptr; name string }
    var rows []row

    for i := uint32(0); i < exportDir.NumberOfNames; i++ {
        nameRva := names[i]
        namePtr := (*[256]byte)(unsafe.Pointer(base + uintptr(nameRva)))
        var name string
        for j := 0; j < 256; j++ {
            if namePtr[j] == 0 { break }
            name += string(namePtr[j])
        }
        if !strings.HasPrefix(name, "Zw") { continue }

        // Try resolving via cached logic (gives SSN + gate); still print original export address
        var s types.Syscall
        ntName := "Nt" + name[2:]
        if !r.Find(ntName, &s) && !r.Find(name, &s) {
            continue
        }
        ordinal := ords[i]
        stub := base + uintptr(funs[ordinal])
        rows = append(rows, row{ssn: s.Nr, addr: stub, name: ntName})
    }

    sort.Slice(rows, func(i, j int) bool { return rows[i].ssn < rows[j].ssn })

    fmt.Printf("SSN\tAddress\t\tName\n")
    fmt.Printf("---\t-------\t\t----\n")
    for _, r := range rows {
        fmt.Printf("%d\t0x%x\t%s\n", r.ssn, r.addr, r.name)
    }
    fmt.Printf("\n[+] found %d syscalls\n", len(rows))
}
