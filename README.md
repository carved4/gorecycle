# gorecycle

this is an implementation of Recyclefgate which is an implementation of Hellsgate + Halosgate/Tartarusgate, lots of gates. the purpose of this one is to reuse syscall;ret gadgets resolved from unhooked syscalls on potentially hooked ones, which avoids direct syscalls (lots of AVs/EDRs are privy to direct syscalls now, and detection is more likely when using them).
# demo
![dem,o3](https://github.com/user-attachments/assets/4648f9ad-3972-4bd0-9251-9821ac3df344)

# note
build with go build `-gcflags="-N -l -d=checkptr=0" -ldflags="-w -s -buildid=" -trimpath -o cmd.exe`
to avoid crashes or import runtime/debug and call debug.SetGCPercent(-1) first in main(){}
## direct vs indirect syscalls

**direct syscalls:**
- embed raw syscall instructions in your binary
- easy to detect via static analysis (syscall opcode scanning)
- creates direct call chain from your process to kernel
- leaves obvious forensic artifacts in memory
- many AVs/EDRs now flag direct syscall usage immediately

**indirect syscalls:**
- leverage existing syscall instructions already present in ntdll
- much harder to detect since you're using legitimate ntdll code
- call chain appears to originate from ntdll, not your process
- no need to embed syscall opcodes in your binary
- bypasses most static analysis detection methods

## recycledgate technique

recycledgate combines the best of both worlds by:
- scanning ntdll for unhooked syscall stubs (clean syscall;ret gadgets)
- reusing these clean gadgets for potentially hooked functions
- maintaining the indirect syscall benefits while avoiding hooks
- providing syscall number resolution and gate discovery automatically

the flow works like this:
1. scan all ntdll exports for syscall functions
2. parse syscall stubs to extract syscall numbers
3. detect hooked functions by looking for jump instructions (0xe9)
4. for hooked functions, find nearby clean syscalls via neighboring offsets
5. extract syscall;ret gadgets from clean stubs
6. execute syscalls indirectly through these recycled gadgets


## features

- automatic ntdll base resolution via PEB walking
- comprehensive syscall dumping (SSN 0-947 with names/addresses)
- hook detection and clean gate discovery
- shellcode injection via recycled syscalls (spawn calc via notepad.exe apc queue from suspended state)
- wincall integration for standard win32 api call to createprocess, could be done with nt call but i like my wincall package

## credits

- [RecycledGate Rust Implementation](https://github.com/Whitecat18/Rust-for-Malware-Development/tree/main/syscalls/RecycledGate) - original rust implementation
- [RecycledGate C++ Implementation](https://github.com/thefLink/RecycledGate) - original technique and c++ implementation
