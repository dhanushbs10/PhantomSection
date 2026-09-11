# PhantomSection

PhantomSection is a C++ shellcode loader that combines PEB walking, Export Address Table (EAT) parsing, and ETW patching to evade userland API hooking and telemetry. Payloads are staged and XOR-encrypted to bypass static signature analysis.

## Features

- API Unhooking via PEB Walking
- Manual Function Resolution via EAT Parsing
- Telemetry Blinding via ETW Patching
- Runtime XOR Payload Decryption

## Technical Overview

### API Unhooking (PEB Walk)
Bypasses `GetModuleHandle` by manually traversing the Process Environment Block (PEB) `InMemoryOrderModuleList` to locate loaded DLL base addresses.

### Manual Resolution (EAT Parse)
Bypasses `GetProcAddress` by parsing the Export Address Table (EAT) of target DLLs. Resolves function addresses directly from PE headers, evading userland API hooks placed by EDRs.

### Telemetry Blinding (ETW Patch)
Overwrites the prologue of `EtwEventWrite` in `ntdll.dll` with a direct return (`xor rax, rax; ret`). This blinds host-based ETW telemetry before the injection sequence occurs.

### Payload Staging & Encryption
The shellcode is XOR-encrypted (Key: 0x55) and stored separately from the loader as `payload.bin`. It is read into memory and decrypted only at runtime. This reduces the entropy of the compiled executable, bypassing static heuristic and signature-based AV scans.

## Execution Flow

1. Loader executable starts.
2. PEB is traversed to find `kernel32.dll` and `ntdll.dll` base addresses.
3. `VirtualAlloc` and `VirtualProtect` are resolved manually via EAT parsing.
4. `EtwEventWrite` is patched in memory to blind host telemetry.
5. Encrypted `payload.bin` is read from disk into a local buffer.
6. Buffer is XOR-decrypted in memory.
7. RWX memory is allocated via the manually resolved `VirtualAlloc`.
8. Decrypted payload is copied to the allocated memory region and executed via function pointer.

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| T1106 | Native API | Manual Function Resolution |
| T1562.001 | Impair Defenses | Disable or Modify Tools (ETW Patching) |
| T1027 | Obfuscated Files or Information | XOR Decryption |
| T1055.001 | Process Injection | Dynamic Invocation |

## Usage

### Prerequisites

- Visual Studio with the Desktop development with C++ workload.
- Kali Linux (for msfvenom and Python) or Windows PowerShell.

### Step 1: Generate Raw Shellcode

Generate the desired raw x64 shellcode. Example using msfvenom in Kali to spawn calc.exe:

```
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o raw.bin
```

### Step 2: Encrypt the Payload

#### Method A: Linux (Python)

Run the provided `encrypt.py` script against the raw shellcode:

```
python3 encrypt.py raw.bin
```

#### Method B: Windows (PowerShell)

Run the provided `encrypt.ps1` script in PowerShell:

```
powershell -ExecutionPolicy Bypass -File .\encrypt.ps1 -InputFile .\raw.bin
```

### Step 3: Compile the Loader

1. Open Visual Studio and create a new C++ Console App project (x64).
2. Replace the contents of the main `.cpp` file with the PhantomSection source code.
3. Compile the project in Release mode, x64.

### Step 4: Execute

1. Place the compiled `PhantomSection.exe` and the generated `payload.bin` in the same directory.
2. Execute `PhantomSection.exe`.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This project is for educational and defensive research purposes only. The techniques demonstrated are intended to understand how threat actors operate so defenders can build better telemetry and mitigations. Do not use this code for unauthorized or malicious purposes.
