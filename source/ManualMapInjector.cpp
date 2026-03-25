//
// Created by Vlad on 6/21/2024.
//
#include "satsuma/ManualMapInjector.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <thread>
#include <fstream>
#include <filesystem>
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#   define RELOC_FLAG RELOC_FLAG64
#else
#   define RELOC_FLAG RELOC_FLAG32
#endif

namespace {

// Extended LDR_DATA_TABLE_ENTRY with fields needed by LdrpHandleTlsData.
// The winternl.h definition is incomplete — this covers the layout up through TlsIndex.
struct LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
};

using LdrpHandleTlsDataFn = NTSTATUS(NTAPI*)(LDR_DATA_TABLE_ENTRY_FULL*);
using RtlInsertInvertedFunctionTableFn = void(NTAPI*)(PVOID ImageBase, ULONG SizeOfImage);

uint8_t* PatternScan(uint8_t* base, size_t size, const uint8_t* pattern, const char* mask)
{
    const size_t patternLen = std::strlen(mask);
    if (size < patternLen)
        return nullptr;

    for (size_t i = 0; i <= size - patternLen; i++)
    {
        bool found = true;
        for (size_t j = 0; j < patternLen; j++)
        {
            if (mask[j] != '?' && pattern[j] != base[i + j])
            {
                found = false;
                break;
            }
        }
        if (found)
            return base + i;
    }
    return nullptr;
}

LdrpHandleTlsDataFn FindLdrpHandleTlsData()
{
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return nullptr;

    const auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdll);
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(ntdll) + dosHeader->e_lfanew);

    auto* base = reinterpret_cast<uint8_t*>(ntdll);
    const size_t size = ntHeaders->OptionalHeader.SizeOfImage;

    // 4C 8B DC 49 89 5B ? 49 89 73 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B F9
    static const uint8_t pattern[] = {
        0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x00, 0x49,
        0x89, 0x73, 0x00, 0x57, 0x41, 0x54, 0x41, 0x55,
        0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00,
        0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF9
    };
    static const char mask[] = "xxxxxx?xxx?xxxxxxxxxxx????xxx????xxxxx????xxxxx";

    if (auto* result = PatternScan(base, size, pattern, mask))
        return reinterpret_cast<LdrpHandleTlsDataFn>(result);

    return nullptr;
}

RtlInsertInvertedFunctionTableFn FindRtlInsertInvertedFunctionTable()
{
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return nullptr;

    const auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdll);
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(ntdll) + dosHeader->e_lfanew);

    auto* base = reinterpret_cast<uint8_t*>(ntdll);
    const size_t size = ntHeaders->OptionalHeader.SizeOfImage;

    // 48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 83 60
    static const uint8_t pattern[] = {
        0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x48,
        0x89, 0x68, 0x00, 0x48, 0x89, 0x70, 0x00, 0x57,
        0x48, 0x83, 0xEC, 0x00, 0x83, 0x60
    };
    static const char mask[] = "xxxxxx?xxx?xxx?xxxx?xx";

    if (auto* result = PatternScan(base, size, pattern, mask))
        return reinterpret_cast<RtlInsertInvertedFunctionTableFn>(result);

    return nullptr;
}

// ---------------------------------------------------------------------------
// Remote injection: shellcode data + self-contained loader
// ---------------------------------------------------------------------------
struct RemoteLoaderData {
    uint8_t* imageBase;
    DWORD    ntHeadersRva;

    decltype(&LoadLibraryA)        fnLoadLibraryA;
    decltype(&GetProcAddress)      fnGetProcAddress;
    decltype(&RtlAddFunctionTable) fnRtlAddFunctionTable;
    void* fnLdrpHandleTlsData;
    void* fnRtlInsertInvertedFunctionTable;
};

// Disable all CRT instrumentation so the function is fully self-contained.
// No __security_check_cookie, no __RTC_*, no __chkstk references.
#pragma runtime_checks("", off)
#pragma optimize("ts", on)
#pragma strict_gs_check(push, off)

__declspec(safebuffers) __declspec(noinline)
static DWORD WINAPI RemoteShellcode(RemoteLoaderData* data)
{
    auto* base = data->imageBase;
    auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(base + data->ntHeadersRva);

    // --- Resolve imports ---
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size)
    {
        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
        while (desc->Characteristics)
        {
            HMODULE hMod = data->fnLoadLibraryA(reinterpret_cast<LPCSTR>(base + desc->Name));
            if (!hMod) return 1;

            auto* ot = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
            auto* ft = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);

            while (ot->u1.AddressOfData)
            {
                FARPROC fn;
                if (ot->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    fn = data->fnGetProcAddress(hMod, reinterpret_cast<LPCSTR>(ot->u1.Ordinal & 0xFFFF));
                else
                {
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + ot->u1.AddressOfData);
                    fn = data->fnGetProcAddress(hMod, ibn->Name);
                }
                if (!fn) return 2;
                ft->u1.Function = reinterpret_cast<uintptr_t>(fn);
                ot++;
                ft++;
            }
            desc++;
        }
    }

    // --- Handle static TLS ---
    auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size && data->fnLdrpHandleTlsData)
    {
        // Build fake LDR_DATA_TABLE_ENTRY on the stack — zero without memset
        LDR_DATA_TABLE_ENTRY_FULL entry;
        auto* raw = reinterpret_cast<volatile uint8_t*>(&entry);
        for (size_t i = 0; i < sizeof(entry); i++)
            raw[i] = 0;

        entry.DllBase     = base;
        entry.SizeOfImage = nt->OptionalHeader.SizeOfImage;
        entry.EntryPoint  = base + nt->OptionalHeader.AddressOfEntryPoint;

        entry.InLoadOrderLinks.Flink              = &entry.InLoadOrderLinks;
        entry.InLoadOrderLinks.Blink              = &entry.InLoadOrderLinks;
        entry.InMemoryOrderLinks.Flink            = &entry.InMemoryOrderLinks;
        entry.InMemoryOrderLinks.Blink            = &entry.InMemoryOrderLinks;
        entry.InInitializationOrderLinks.Flink    = &entry.InInitializationOrderLinks;
        entry.InInitializationOrderLinks.Blink    = &entry.InInitializationOrderLinks;
        entry.HashLinks.Flink                     = &entry.HashLinks;
        entry.HashLinks.Blink                     = &entry.HashLinks;

        reinterpret_cast<NTSTATUS(NTAPI*)(LDR_DATA_TABLE_ENTRY_FULL*)>(
            data->fnLdrpHandleTlsData)(&entry);
    }

    // --- TLS callbacks ---
    if (tlsDir.Size)
    {
        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + tlsDir.VirtualAddress);
        auto* cb  = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        for (; cb && *cb; cb++)
            (*cb)(base, DLL_PROCESS_ATTACH, nullptr);
    }

    // --- Exception handling ---
    auto& excDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (excDir.Size)
    {
        if (data->fnRtlInsertInvertedFunctionTable)
        {
            reinterpret_cast<void(NTAPI*)(PVOID, ULONG)>(
                data->fnRtlInsertInvertedFunctionTable)(base, nt->OptionalHeader.SizeOfImage);
        }
        else
        {
            data->fnRtlAddFunctionTable(
                reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(base + excDir.VirtualAddress),
                excDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
                reinterpret_cast<uintptr_t>(base));
        }
    }

    // --- Call entry point ---
    if (nt->OptionalHeader.AddressOfEntryPoint)
    {
        auto ep = reinterpret_cast<BOOL(WINAPI*)(HMODULE, DWORD, LPVOID)>(
            base + nt->OptionalHeader.AddressOfEntryPoint);
        ep(reinterpret_cast<HMODULE>(base), DLL_PROCESS_ATTACH, nullptr);
    }

    return 0;
}

static void RemoteShellcodeEnd() { }

#pragma strict_gs_check(pop)
#pragma runtime_checks("", restore)
#pragma optimize("", on)

// Resolve MSVC incremental-link jump stubs (ILT): E9 xx xx xx xx → target
static uint8_t* ResolveILT(void* fn)
{
    auto* p = static_cast<uint8_t*>(fn);
    if (p[0] == 0xE9)
    {
        auto rel = *reinterpret_cast<int32_t*>(p + 1);
        return p + 5 + rel;
    }
    return p;
}

// Apply relocations to a local buffer using an arbitrary target base address
static void RelocateForBase(uint8_t* localImage, uintptr_t targetBase)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(localImage);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(localImage + dos->e_lfanew);

    const auto delta = static_cast<intptr_t>(targetBase - nt->OptionalHeader.ImageBase);
    if (delta == 0)
        return;

    auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir.Size)
        return;

    auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(localImage + relocDir.VirtualAddress);
    while (block->SizeOfBlock && block->VirtualAddress)
    {
        const size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto* info = reinterpret_cast<uint16_t*>(block + 1);
        for (size_t i = 0; i < count; i++, info++)
        {
            if (!RELOC_FLAG(*info))
                continue;
            auto* patch = reinterpret_cast<uintptr_t*>(localImage + block->VirtualAddress + (*info & 0xFFF));
            *patch += delta;
        }
        block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uint8_t*>(block) + block->SizeOfBlock);
    }

    nt->OptionalHeader.ImageBase = targetBase;
}

} // anonymous namespace

bool satsuma::ManualMapInjector::HandleStaticTLS(const satsuma::ImagePtr& image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get() + dosHeaders->e_lfanew);

    const auto& tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!tlsDir.Size)
        return true; // no TLS directory, nothing to do

    static const auto ldrpHandleTlsData = FindLdrpHandleTlsData();
    if (!ldrpHandleTlsData)
        return false;

    // Build a fake LDR_DATA_TABLE_ENTRY so LdrpHandleTlsData can read the PE's TLS directory
    LDR_DATA_TABLE_ENTRY_FULL fakeEntry{};
    fakeEntry.DllBase = image.get();
    fakeEntry.SizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    fakeEntry.EntryPoint = image.get() + ntHeaders->OptionalHeader.AddressOfEntryPoint;

    // Self-referencing list entries so the loader doesn't walk into invalid memory
    fakeEntry.InLoadOrderLinks.Flink = &fakeEntry.InLoadOrderLinks;
    fakeEntry.InLoadOrderLinks.Blink = &fakeEntry.InLoadOrderLinks;
    fakeEntry.InMemoryOrderLinks.Flink = &fakeEntry.InMemoryOrderLinks;
    fakeEntry.InMemoryOrderLinks.Blink = &fakeEntry.InMemoryOrderLinks;
    fakeEntry.InInitializationOrderLinks.Flink = &fakeEntry.InInitializationOrderLinks;
    fakeEntry.InInitializationOrderLinks.Blink = &fakeEntry.InInitializationOrderLinks;
    fakeEntry.HashLinks.Flink = &fakeEntry.HashLinks;
    fakeEntry.HashLinks.Blink = &fakeEntry.HashLinks;

    const NTSTATUS status = ldrpHandleTlsData(&fakeEntry);
    return status >= 0; // NT_SUCCESS
}

bool satsuma::ManualMapInjector::IsPortableExecutable(const std::span<uint8_t> &rawDll)
{

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawDll.data());

    if (dosHeaders->e_magic != 0x5A4D)
        return false;

    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawDll.data()+dosHeaders->e_lfanew);

    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return false;

    return true;
}

satsuma::ImagePtr satsuma::ManualMapInjector::AllocatePortableExecutableImage(const std::span<uint8_t> &rawDll)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawDll.data());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawDll.data()+dosHeaders->e_lfanew);

    auto* mem = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    assert(mem);

    return ImagePtr(mem);
}

void satsuma::ManualMapInjector::MaybeRelocate(const satsuma::ImagePtr &image)
{

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    const uintptr_t diff = reinterpret_cast<uintptr_t>(image.get()) - ntHeaders->OptionalHeader.ImageBase;

    if (diff == 0)
        return;

    const auto& baseReloc = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!baseReloc.Size)
        return;

    auto* currentBaseRelocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image.get() + baseReloc.VirtualAddress);
    while (currentBaseRelocation->SizeOfBlock && currentBaseRelocation->VirtualAddress)
    {
        const size_t entries = (currentBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto relativeInfo = reinterpret_cast<uint16_t*>(currentBaseRelocation + 1);

        for (size_t i = 0; i < entries; i++, relativeInfo++)
        {
            if (!RELOC_FLAG(*relativeInfo))
                continue;

            auto* pPatch = reinterpret_cast<uintptr_t*>(image.get() + currentBaseRelocation->VirtualAddress + (*relativeInfo & 0xFFF));
            *pPatch += static_cast<uintptr_t>(diff);
        }
        currentBaseRelocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(currentBaseRelocation) + currentBaseRelocation->SizeOfBlock);
    }
}

void satsuma::ManualMapInjector::CopyPages(const std::span<uint8_t> &rawDll, const satsuma::ImagePtr &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawDll.data());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawDll.data()+dosHeaders->e_lfanew);

    auto currentSection = IMAGE_FIRST_SECTION(ntHeaders);

    for (size_t i = 0; i != ntHeaders->FileHeader.NumberOfSections; ++i, ++currentSection)
    {
        if (!currentSection->SizeOfRawData)
            continue;

        std::ranges::copy_n(rawDll.data() + currentSection->PointerToRawData,
                            currentSection->SizeOfRawData, image.get() + currentSection->VirtualAddress);
    }
}


bool satsuma::ManualMapInjector::CreateImportTable(const satsuma::ImagePtr &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);


    auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image.get() + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDescriptor->Characteristics)
    {
        auto origFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(image.get() + importDescriptor->OriginalFirstThunk);
        auto firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(image.get() + importDescriptor->FirstThunk);

        const HMODULE hModule = LoadLibraryA(reinterpret_cast<LPCSTR>(image.get()) + importDescriptor->Name);

        if (!hModule)
            return false;

        while (origFirstThunk->u1.AddressOfData)
        {
            if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                const auto ordinal = GetProcAddress(hModule, reinterpret_cast<LPCSTR>(origFirstThunk->u1.Ordinal & 0xFFFF));

                if (!ordinal)
                    return false;

                firstThunk->u1.Function = reinterpret_cast<uintptr_t>(ordinal);
            }
            else
            {
                const auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image.get() + origFirstThunk->u1.AddressOfData);
                const auto function = GetProcAddress(hModule, ibn->Name);

                if (!function)
                    return false;

                firstThunk->u1.Function = reinterpret_cast<uintptr_t>(function);
            }
            origFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }
    return true;
}

void satsuma::ManualMapInjector::MaybeCallTLSCallbacks(const satsuma::ImagePtr &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    const auto& [VirtualAddress, Size] = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (!Size)
        return;

    const auto* tlsDirectory = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(image.get() + VirtualAddress);
    const auto* callBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDirectory->AddressOfCallBacks);

    for (; callBack && *callBack; callBack++)
        (*callBack)(image.get(), DLL_PROCESS_ATTACH, nullptr);
}

void satsuma::ManualMapInjector::EnableExceptions(const satsuma::ImagePtr &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    const auto& [VirtualAddress, Size] = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!Size)
        return;

    // RtlInsertInvertedFunctionTable registers the image in ntdll's inverted function
    // table, which is what the MSVC C++ exception runtime (__CxxFrameHandler) uses.
    // RtlAddFunctionTable only covers SEH — C++ exceptions need the inverted table.
    static const auto rtlInsertInvertedFunctionTable = FindRtlInsertInvertedFunctionTable();
    if (rtlInsertInvertedFunctionTable)
    {
        rtlInsertInvertedFunctionTable(image.get(), ntHeaders->OptionalHeader.SizeOfImage);
        return;
    }

    // Fallback: at least SEH will work
    RtlAddFunctionTable(reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(image.get() + VirtualAddress),
            Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<uintptr_t>(image.get()));
}

std::optional<std::function<int(HMODULE, DWORD, LPVOID)>> satsuma::ManualMapInjector::MaybeGetEntryPoint(const satsuma::ImagePtr& image)
{

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    typedef int(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

    if (!ntHeaders->OptionalHeader.AddressOfEntryPoint)
        return std::nullopt;

    return reinterpret_cast<dllmain>(image.get() + ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

std::expected<satsuma::ImagePtr, std::string>  satsuma::ManualMapInjector::InjectFromRaw(const std::span<uint8_t> &rawDll)
{

    if (!IsPortableExecutable(rawDll))
        return std::unexpected("File is not in a Portable Executable format");

    auto imageBaseAddress = AllocatePortableExecutableImage(rawDll);

    const auto* dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawDll.data());
    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawDll.data() + dosHeaders->e_lfanew);

    std::ranges::copy_n(rawDll.cbegin(), ntHeaders->OptionalHeader.SizeOfHeaders, imageBaseAddress.get());

    CopyPages(rawDll, imageBaseAddress);
    MaybeRelocate(imageBaseAddress);

    if (!CreateImportTable(imageBaseAddress))
        return std::unexpected("Failed to create Import Table");

    if (!HandleStaticTLS(imageBaseAddress))
        return std::unexpected("Failed to initialize static TLS via LdrpHandleTlsData");

    MaybeCallTLSCallbacks(imageBaseAddress);
    EnableExceptions(imageBaseAddress);

    if (const auto entryPoint = MaybeGetEntryPoint(imageBaseAddress))
        std::thread(*entryPoint, reinterpret_cast<HMODULE>(imageBaseAddress.get()), DLL_PROCESS_ATTACH, nullptr).join();

    return imageBaseAddress;
}

std::expected<satsuma::ImagePtr, std::string>  satsuma::ManualMapInjector::InjectFromFile(const std::string &pathToDll)
{
    std::vector<uint8_t> data(std::filesystem::file_size(pathToDll), 0);

    std::ifstream file(pathToDll, std::ios::binary);

    if (!file.is_open())
        return nullptr;

    file.read(reinterpret_cast<char *>(data.data()), data.size());

    return InjectFromRaw({data.data(), data.size()});
}

// =========================================================================
// Remote injection
// =========================================================================

DWORD satsuma::ManualMapInjector::FindProcessId(const std::string &processName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32First(snap, &pe))
    {
        do
        {
            if (_stricmp(pe.szExeFile, processName.c_str()) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

std::expected<uintptr_t, std::string>
satsuma::ManualMapInjector::InjectRemoteFromRaw(const std::span<uint8_t> &rawDll, DWORD processId)
{
    if (!IsPortableExecutable(rawDll))
        return std::unexpected("File is not in a Portable Executable format");

    // Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, processId);

    if (!hProcess)
        return std::unexpected("Failed to open target process (error " + std::to_string(GetLastError()) + ")");

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawDll.data());
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawDll.data() + dos->e_lfanew);
    const DWORD imageSize = nt->OptionalHeader.SizeOfImage;

    // Allocate image memory in target process
    auto* remoteImage = static_cast<uint8_t*>(VirtualAllocEx(
        hProcess, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!remoteImage)
    {
        CloseHandle(hProcess);
        return std::unexpected("VirtualAllocEx failed for image (error " + std::to_string(GetLastError()) + ")");
    }

    // Prepare local copy: headers + sections
    std::vector<uint8_t> localImage(imageSize, 0);
    std::copy_n(rawDll.data(), nt->OptionalHeader.SizeOfHeaders, localImage.data());

    auto* secHeader = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, secHeader++)
    {
        if (!secHeader->SizeOfRawData)
            continue;
        std::copy_n(rawDll.data() + secHeader->PointerToRawData,
                     secHeader->SizeOfRawData,
                     localImage.data() + secHeader->VirtualAddress);
    }

    // Relocate for remote base address
    RelocateForBase(localImage.data(), reinterpret_cast<uintptr_t>(remoteImage));

    // Write image to target
    if (!WriteProcessMemory(hProcess, remoteImage, localImage.data(), imageSize, nullptr))
    {
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return std::unexpected("WriteProcessMemory failed for image");
    }

    // Prepare shellcode page: [RemoteLoaderData | padding | shellcode bytes]
    auto* scBody  = ResolveILT(reinterpret_cast<void*>(&RemoteShellcode));
    auto* scEnd   = ResolveILT(reinterpret_cast<void*>(&RemoteShellcodeEnd));
    size_t scSize = static_cast<size_t>(scEnd - scBody);
    if (scSize < 0x100) scSize = 0x1000; // safety floor

    constexpr size_t dataAligned = (sizeof(RemoteLoaderData) + 0xF) & ~0xF;
    const size_t totalShellcode  = dataAligned + scSize;

    auto* remoteShellcode = static_cast<uint8_t*>(VirtualAllocEx(
        hProcess, nullptr, totalShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (!remoteShellcode)
    {
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return std::unexpected("VirtualAllocEx failed for shellcode");
    }

    // Fill loader data
    // ntdll and kernel32 are mapped at the same base in every process (per boot),
    // so our local function pointers are valid in the target.
    auto* localDos = reinterpret_cast<IMAGE_DOS_HEADER*>(localImage.data());

    RemoteLoaderData loaderData{};
    loaderData.imageBase      = remoteImage;
    loaderData.ntHeadersRva   = static_cast<DWORD>(localDos->e_lfanew);
    loaderData.fnLoadLibraryA = LoadLibraryA;
    loaderData.fnGetProcAddress = GetProcAddress;
    loaderData.fnRtlAddFunctionTable = RtlAddFunctionTable;
    loaderData.fnLdrpHandleTlsData = reinterpret_cast<void*>(FindLdrpHandleTlsData());
    loaderData.fnRtlInsertInvertedFunctionTable = reinterpret_cast<void*>(FindRtlInsertInvertedFunctionTable());

    // Build local shellcode page
    std::vector<uint8_t> scPage(totalShellcode, 0);
    std::memcpy(scPage.data(), &loaderData, sizeof(loaderData));
    std::memcpy(scPage.data() + dataAligned, scBody, scSize);

    // Write shellcode page to target
    if (!WriteProcessMemory(hProcess, remoteShellcode, scPage.data(), totalShellcode, nullptr))
    {
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return std::unexpected("WriteProcessMemory failed for shellcode");
    }

    // Create remote thread: entry = shellcode code, param = RemoteLoaderData*
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteShellcode + dataAligned),
        remoteShellcode, // lpParameter → points to RemoteLoaderData
        0, nullptr);

    if (!hThread)
    {
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return std::unexpected("CreateRemoteThread failed (error " + std::to_string(GetLastError()) + ")");
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    // Free shellcode page — no longer needed after init
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (exitCode != 0)
        return std::unexpected("Remote shellcode failed (exit code " + std::to_string(exitCode) + ")");

    return reinterpret_cast<uintptr_t>(remoteImage);
}

std::expected<uintptr_t, std::string>
satsuma::ManualMapInjector::InjectRemoteFromFile(const std::string &pathToDll, const std::string &processName)
{
    const DWORD pid = FindProcessId(processName);
    if (!pid)
        return std::unexpected("Process \"" + processName + "\" not found");

    std::vector<uint8_t> data(std::filesystem::file_size(pathToDll), 0);
    std::ifstream file(pathToDll, std::ios::binary);
    if (!file.is_open())
        return std::unexpected("Failed to open DLL file");

    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return InjectRemoteFromRaw({data.data(), data.size()}, pid);
}
