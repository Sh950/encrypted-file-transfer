#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace FileUtils
{
	// Directory of client.exe - transfer.json and me.info live there, not in the current directory.
	std::filesystem::path getExecutableDirectory();

	std::string readTextFile(const std::filesystem::path& path, std::uintmax_t maxSize);
}