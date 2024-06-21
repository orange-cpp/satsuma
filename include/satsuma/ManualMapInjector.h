//
// Created by Vlad on 6/21/2024.
//

#pragma once
#include <memory>
#include <functional>
#include <Windows.h>

#include "Injector.h"


namespace satsuma
{
    class ManualMapInjector final : public Injector
    {
    public:
        [[nodiscard]]
        std::unique_ptr<uint8_t[]> InjectFromRaw(const std::span<uint8_t> &rawDll, const std::string &processName) const override;

        [[nodiscard]]
        std::unique_ptr<uint8_t[]>  InjectFromFile(const std::string &pathToDll, const std::string &processName) const override;

    private:
        [[nodiscard]]
        static bool IsPortableExecutable(const std::span<uint8_t> &rawDll);

        [[nodiscard]]
        static std::unique_ptr<uint8_t[]> AllocatePortableExecutableImage(const std::span<uint8_t> &rawDll);

        static void MaybeRelocate(const std::unique_ptr<uint8_t[]>& image);

        static void CopyPages(const std::span<uint8_t> & rawDll, const std::unique_ptr<uint8_t[]>& image);

        static void CreateImportTable(const std::unique_ptr<uint8_t[]>& image);

        static void CallTLSCallbacks(const std::unique_ptr<uint8_t[]>& image);


        static void EnableExceptions(const std::unique_ptr<uint8_t[]>& image);
        [[nodiscard]]
        static std::function<int(HMODULE, DWORD, LPVOID)> GetEntryPoint(const std::unique_ptr<uint8_t[]>& image);
    };
}