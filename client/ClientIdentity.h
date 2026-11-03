#pragma once
#include "Protocol.h"

#include <string>
#include <optional>
#include <filesystem>


struct ClientIdentity
{
	std::string name;
	Protocol::ClientId id;
	std::string privateKey;  // DER bytes, not Base64
};

std::optional<ClientIdentity> loadIdentity(const std::filesystem::path& directory);
void saveIdentity(const std::filesystem::path& directory, const ClientIdentity& identity);
void deleteIdentity(const std::filesystem::path& directory);