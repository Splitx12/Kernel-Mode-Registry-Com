#pragma once

class RegistryHelper
{
public:
    auto RegistryQueryValue(
        IN PREGISTRY_INFORMATION pRegistryInformation
    ) -> NTSTATUS;
};