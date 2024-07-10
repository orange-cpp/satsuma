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
    class ManualMapInjector final
    {
    public:
        [[nodiscard]]
        static std::expected<std::unique_ptr<uint8_t[]>, std::string> InjectFromRaw(const std::span<uint8_t> &rawDll);

        [[nodiscard]]
        static std::expected<std::unique_ptr<uint8_t[]>, std::string>  InjectFromFile(const std::string &pathToDll);

    private:
        [[nodiscard]]
        static bool __declspec(noinline) IsPortableExecutable(const std::span<uint8_t> &rawDll);

        [[nodiscard]]
        static __declspec(noinline) std::unique_ptr<uint8_t[]> AllocatePortableExecutableImage(const std::span<uint8_t> &rawDll);


        static __declspec(noinline) void MaybeRelocate(const std::unique_ptr<uint8_t[]>& image);

        static __declspec(noinline) void CopyPages(const std::span<uint8_t> & rawDll, const std::unique_ptr<uint8_t[]>& image);

        [[nodiscard]]
        static __declspec(noinline) bool CreateImportTable(const std::unique_ptr<uint8_t[]>& image);

        static __declspec(noinline) void MaybeCallTLSCallbacks(const std::unique_ptr<uint8_t[]>& image);

        static __declspec(noinline) void EnableExceptions(const std::unique_ptr<uint8_t[]>& image);

        [[nodiscard]]
        static std::optional<std::function<int(HMODULE, DWORD, LPVOID)>> MaybeGetEntryPoint(const std::unique_ptr<uint8_t[]>& image);
    };
}