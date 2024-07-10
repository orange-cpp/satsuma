//
// Created by Vlad on 6/21/2024.
//
#include "satsuma/xorstr.h"

#include "satsuma/ManualMapInjector.h"

#include <algorithm>
#include <cassert>
#include <memory>
#include <Windows.h>
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

#ifndef USE_VIRTUALIZER
#   define VIRTUALIZER_START
#   define VIRTUALIZER_END
#else
#   include <CodeVirtualizer/VirtualizerSDK.h>
#endif


bool satsuma::ManualMapInjector::IsPortableExecutable(const std::span<uint8_t> &rawDll)
{
    VIRTUALIZER_START

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawDll.data());

    if (dosHeaders->e_magic != 0x5A4D)
        return false;

    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawDll.data()+dosHeaders->e_lfanew);

    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return false;

    VIRTUALIZER_END
    return true;
}

std::unique_ptr<uint8_t[]> satsuma::ManualMapInjector::AllocatePortableExecutableImage(const std::span<uint8_t> &rawDll)
{
    VIRTUALIZER_START

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawDll.data());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(rawDll.data()+dosHeaders->e_lfanew);

    auto imageBaseAddress = std::make_unique<uint8_t[]>(ntHeaders->OptionalHeader.SizeOfImage);

    if (!imageBaseAddress)
        assert(false);

    DWORD oldProc;
    VirtualProtect(imageBaseAddress.get(), ntHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProc);

    VIRTUALIZER_END
    return imageBaseAddress;
}

void satsuma::ManualMapInjector::MaybeRelocate(const std::unique_ptr<uint8_t[]> &image)
{
    VIRTUALIZER_START
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
    VIRTUALIZER_END
}

void satsuma::ManualMapInjector::CopyPages(const std::span<uint8_t> &rawDll, const std::unique_ptr<uint8_t[]> &image)
{
    VIRTUALIZER_START

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
    VIRTUALIZER_END
}


bool satsuma::ManualMapInjector::CreateImportTable(const std::unique_ptr<uint8_t[]> &image)
{
    VIRTUALIZER_START

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
    VIRTUALIZER_END
    return true;
}

void satsuma::ManualMapInjector::MaybeCallTLSCallbacks(const std::unique_ptr<uint8_t[]> &image)
{
    VIRTUALIZER_START

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    const auto& [VirtualAddress, Size] = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (!Size)
        return;

    const auto* tlsDirectory = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(image.get() + VirtualAddress);
    const auto* callBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDirectory->AddressOfCallBacks);

    for (; callBack && *callBack; callBack++)
        (*callBack)(image.get(), DLL_PROCESS_ATTACH, nullptr);

    VIRTUALIZER_END
}

void satsuma::ManualMapInjector::EnableExceptions(const std::unique_ptr<uint8_t[]> &image)
{
    VIRTUALIZER_START

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    const auto& [VirtualAddress, Size] = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!Size)
        return;
    auto result = RtlAddFunctionTable(
            reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(image.get() + VirtualAddress),
            Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<uintptr_t>(image.get()));

    VIRTUALIZER_END
}

std::optional<std::function<int(HMODULE, DWORD, LPVOID)>> satsuma::ManualMapInjector::MaybeGetEntryPoint(const std::unique_ptr<uint8_t[]>& image)
{
    VIRTUALIZER_START

    const auto dosHeaders = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.get());
    const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.get()+dosHeaders->e_lfanew);

    typedef int(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

    if (!ntHeaders->OptionalHeader.AddressOfEntryPoint)
        return std::nullopt;

    VIRTUALIZER_END

    return reinterpret_cast<dllmain>(image.get() + ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

std::expected<std::unique_ptr<uint8_t[]>, std::string>  satsuma::ManualMapInjector::InjectFromRaw(const std::span<uint8_t> &rawDll)
{
    VIRTUALIZER_START
    if (!IsPortableExecutable(rawDll))
        return std::unexpected(xorstr_("File is not in a Portable Executable format"));

    auto imageBaseAddress = AllocatePortableExecutableImage(rawDll);

    constexpr size_t sizeOfHeader = 0x1000;

    std::ranges::copy_n(rawDll.cbegin(), sizeOfHeader, imageBaseAddress.get());

    CopyPages(rawDll, imageBaseAddress);
    MaybeRelocate(imageBaseAddress);

    if (!CreateImportTable(imageBaseAddress))
        return std::unexpected(xorstr_("Failed to create Import Table"));

    MaybeCallTLSCallbacks(imageBaseAddress);
    EnableExceptions(imageBaseAddress);

    if (const auto entryPoint = MaybeGetEntryPoint(imageBaseAddress))
        std::thread(*entryPoint, reinterpret_cast<HMODULE>(imageBaseAddress.get()), DLL_PROCESS_ATTACH, nullptr).join();

    VIRTUALIZER_END

    return imageBaseAddress;
}

std::expected<std::unique_ptr<uint8_t[]>, std::string>  satsuma::ManualMapInjector::InjectFromFile(const std::string &pathToDll)
{
    VIRTUALIZER_START

    std::vector<uint8_t> data(std::filesystem::file_size(pathToDll), 0);

    std::ifstream file(pathToDll, std::ios::binary);

    if (!file.is_open())
        return nullptr;

    file.read(reinterpret_cast<char *>(data.data()), data.size());

    VIRTUALIZER_END

    return InjectFromRaw({data.data(), data.size()});
}
