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
    class ManualMapInjector final : public Injector
    {
    public:
        [[nodiscard]]
        std::expected<std::unique_ptr<uint8_t[]>, std::string> InjectFromRaw(const std::span<uint8_t> &rawDll) const override;

        [[nodiscard]]
        std::expected<std::unique_ptr<uint8_t[]>, std::string>  InjectFromFile(const std::string &pathToDll) const override;

    private:
        [[nodiscard]]
        static bool IsPortableExecutable(const std::span<uint8_t> &rawDll);

        [[nodiscard]]
        static std::unique_ptr<uint8_t[]> AllocatePortableExecutableImage(const std::span<uint8_t> &rawDll);


        static void MaybeRelocate(const std::unique_ptr<uint8_t[]>& image);

        static void CopyPages(const std::span<uint8_t> & rawDll, const std::unique_ptr<uint8_t[]>& image);

        [[nodiscard]]
        static bool CreateImportTable(const std::unique_ptr<uint8_t[]>& image);

        static void MaybeCallTLSCallbacks(const std::unique_ptr<uint8_t[]>& image);

        static void EnableExceptions(const std::unique_ptr<uint8_t[]>& image);

        [[nodiscard]]
        static std::optional<std::function<int(HMODULE, DWORD, LPVOID)>> MaybeGetEntryPoint(const std::unique_ptr<uint8_t[]>& image);
    };
}