#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// Every field is validated by loadTransferConfig: if it returns, the config is usable.
struct TransferConfig
{
	std::string ip;
	uint16_t    port;
	std::string clientName;
	std::vector<std::filesystem::path> files;
};

TransferConfig loadTransferConfig(const std::filesystem::path& path);