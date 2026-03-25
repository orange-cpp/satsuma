//
// Created by Vlad on 6/21/2024.
//

#pragma once
#include <memory>
#include <functional>
#include <optional>
#include <Windows.h>

#include "Injector.h"


namespace satsuma
{
    struct VirtualFreeDeleter
    {
        void operator()(uint8_t* p) const noexcept
        {
            if (p) VirtualFree(p, 0, MEM_RELEASE);
        }
    };

    using ImagePtr = std::unique_ptr<uint8_t[], VirtualFreeDeleter>;

    class ManualMapInjector final
    {
    public:
        [[nodiscard]]
        static std::expected<ImagePtr, std::string> InjectFromRaw(const std::span<uint8_t> &rawDll);

        [[nodiscard]]
        static std::expected<ImagePtr, std::string> InjectFromFile(const std::string &pathToDll);

    private:
        [[nodiscard]]
        static bool IsPortableExecutable(const std::span<uint8_t> &rawDll);

        [[nodiscard]]
        static ImagePtr AllocatePortableExecutableImage(const std::span<uint8_t> &rawDll);

        static void MaybeRelocate(const ImagePtr& image);

        static void CopyPages(const std::span<uint8_t> & rawDll, const ImagePtr& image);

        [[nodiscard]]
        static bool CreateImportTable(const ImagePtr& image);

        static void MaybeCallTLSCallbacks(const ImagePtr& image);

        static bool HandleStaticTLS(const ImagePtr& image);

        static void EnableExceptions(const ImagePtr& image);

        [[nodiscard]]
        static std::optional<std::function<int(HMODULE, DWORD, LPVOID)>> MaybeGetEntryPoint(const ImagePtr& image);
    };
}