//
// Created by Vlad on 6/21/2024.
//
#include "satsuma/ManualMapInjector.h"

#include <algorithm>
#include <cassert>
#include <memory>
#include <Windows.h>
#include <thread>


#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

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
        assert(false);

    const auto& baseReloc = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (baseReloc.Size == 0)
        assert(false);

    auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image.get() + baseReloc.VirtualAddress);
    while (pRelocData->SizeOfBlock)
    {
        const size_t entries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto pRelativeInfo = reinterpret_cast<uint16_t*>(pRelocData + 1);

        for (size_t i = 0; i != entries; ++i, ++pRelativeInfo)
        {
            if (RELOC_FLAG(*pRelativeInfo)) {
                auto* pPatch = reinterpret_cast<uintptr_t*>(image.get() + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));

                *pPatch += static_cast<uintptr_t>(diff);
            }
        }
        pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
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


void satsuma::ManualMapInjector::CreateImportTable(const std::unique_ptr<uint8_t[]> &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);


    auto pIID = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image.get() + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Resolve DLL imports
    while (pIID->Characteristics)
    {
        auto OrigFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(image.get() + pIID->OriginalFirstThunk);
        auto FirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(image.get() + pIID->FirstThunk);

        const HMODULE hModule = LoadLibraryA(reinterpret_cast<LPCSTR>(image.get()) + pIID->Name);

        if (!hModule)
            assert(false);

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                const auto ordinal = reinterpret_cast<uintptr_t>(GetProcAddress(hModule, reinterpret_cast<LPCSTR>(OrigFirstThunk->u1.Ordinal & 0xFFFF)));

                if (!ordinal)
                    assert(false);

                FirstThunk->u1.Function = ordinal;
            }
            else
            {
                auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image.get() + OrigFirstThunk->u1.AddressOfData);
                auto function = reinterpret_cast<uintptr_t>(GetProcAddress(hModule, ibn->Name));

                if (!function)
                    assert(false);

                FirstThunk->u1.Function = function;
            }
            OrigFirstThunk++;
            FirstThunk++;
        }
        pIID++;
    }
}

void satsuma::ManualMapInjector::CallTLSCallbacks(const std::unique_ptr<uint8_t[]> &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    const auto& tlsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (!tlsDir.Size)
        return;

    const auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(image.get() + tlsDir.VirtualAddress);
    const auto* callBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

    for (; callBack && *callBack; callBack++)
        (*callBack)(image.get(), DLL_PROCESS_ATTACH, nullptr);

}

void satsuma::ManualMapInjector::EnableExceptions(const std::unique_ptr<uint8_t[]> &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    auto excep = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!excep.Size)
        return;
    RtlAddFunctionTable(
            reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(image.get() + excep.VirtualAddress),
            excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<uintptr_t>(image.get()));
}

std::function<int(HMODULE, DWORD, LPVOID)> satsuma::ManualMapInjector::GetEntryPoint(
    const std::unique_ptr<uint8_t[]> &image)
{
    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    typedef int(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

    return reinterpret_cast<dllmain>(image.get() + ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

std::unique_ptr<uint8_t[]> satsuma::ManualMapInjector::InjectFromRaw(const std::span<uint8_t> &rawDll, const std::string &processName) const
{
    if (!IsPortableExecutable(rawDll))
        return nullptr;

    auto imageBaseAddress = AllocatePortableExecutableImage(rawDll);

    constexpr size_t sizeOfHeader = 0x1000;

    std::ranges::copy_n(rawDll.cbegin(), sizeOfHeader, imageBaseAddress.get());

    CopyPages(rawDll, imageBaseAddress);
    MaybeRelocate(imageBaseAddress);
    CreateImportTable(imageBaseAddress);
    CallTLSCallbacks(imageBaseAddress);
    EnableExceptions(imageBaseAddress);

    std::thread(GetEntryPoint(imageBaseAddress), reinterpret_cast<HMODULE>(imageBaseAddress.get()), DLL_PROCESS_ATTACH, nullptr).join();

    return imageBaseAddress;
}

std::unique_ptr<uint8_t[]> satsuma::ManualMapInjector::InjectFromFile(const std::string &pathToDll, const std::string &processName) const
{
    return nullptr;
}
