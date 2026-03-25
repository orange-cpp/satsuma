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

} // anonymous namespace

bool satsuma::ManualMapInjector::HandleStaticTLS(const std::unique_ptr<uint8_t[]>& image)
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

std::unique_ptr<uint8_t[]> satsuma::ManualMapInjector::AllocatePortableExecutableImage(const std::span<uint8_t> &rawDll)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawDll.data());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawDll.data()+dosHeaders->e_lfanew);

    auto imageBaseAddress = std::make_unique<uint8_t[]>(ntHeaders->OptionalHeader.SizeOfImage);

    if (!imageBaseAddress)
        assert(false);

    DWORD oldProc;
    VirtualProtect(imageBaseAddress.get(), ntHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProc);

    return imageBaseAddress;
}

void satsuma::ManualMapInjector::MaybeRelocate(const std::unique_ptr<uint8_t[]> &image)
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

        for (size_t i = 0; i <= entries; i++, relativeInfo++)
        {
            if (!RELOC_FLAG(*relativeInfo))
                continue;

            auto* pPatch = reinterpret_cast<uintptr_t*>(image.get() + currentBaseRelocation->VirtualAddress + (*relativeInfo & 0xFFF));
            *pPatch += static_cast<uintptr_t>(diff);
        }
        currentBaseRelocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(currentBaseRelocation) + currentBaseRelocation->SizeOfBlock);
    }
}

void satsuma::ManualMapInjector::CopyPages(const std::span<uint8_t> &rawDll, const std::unique_ptr<uint8_t[]> &image)
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


bool satsuma::ManualMapInjector::CreateImportTable(const std::unique_ptr<uint8_t[]> &image)
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

void satsuma::ManualMapInjector::MaybeCallTLSCallbacks(const std::unique_ptr<uint8_t[]> &image)
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

void satsuma::ManualMapInjector::EnableExceptions(const std::unique_ptr<uint8_t[]> &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    const auto& [VirtualAddress, Size] = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!Size)
        return;

    RtlAddFunctionTable(reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(image.get() + VirtualAddress),
            Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<uintptr_t>(image.get()));
}

std::optional<std::function<int(HMODULE, DWORD, LPVOID)>> satsuma::ManualMapInjector::MaybeGetEntryPoint(const std::unique_ptr<uint8_t[]>& image)
{

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    typedef int(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

    if (!ntHeaders->OptionalHeader.AddressOfEntryPoint)
        return std::nullopt;

    return reinterpret_cast<dllmain>(image.get() + ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

std::expected<std::unique_ptr<uint8_t[]>, std::string>  satsuma::ManualMapInjector::InjectFromRaw(const std::span<uint8_t> &rawDll)
{

    if (!IsPortableExecutable(rawDll))
        return std::unexpected("File is not in a Portable Executable format");

    auto imageBaseAddress = AllocatePortableExecutableImage(rawDll);

    constexpr size_t sizeOfHeader = 0x1000;

    std::ranges::copy_n(rawDll.cbegin(), sizeOfHeader, imageBaseAddress.get());

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

std::expected<std::unique_ptr<uint8_t[]>, std::string>  satsuma::ManualMapInjector::InjectFromFile(const std::string &pathToDll)
{
    std::vector<uint8_t> data(std::filesystem::file_size(pathToDll), 0);

    std::ifstream file(pathToDll, std::ios::binary);

    if (!file.is_open())
        return nullptr;

    file.read(reinterpret_cast<char *>(data.data()), data.size());

    return InjectFromRaw({data.data(), data.size()});
}
