#include "FileUtils.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <fstream>
#include <stdexcept>
#include <vector>

namespace FileUtils
{
	std::filesystem::path getExecutableDirectory()
	{
		constexpr size_t MAX_WINDOWS_PATH = 32768;
		std::vector<wchar_t> buffer(MAX_PATH);

		while (true)
		{
			const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
			if (length == 0)
				throw std::runtime_error("getExecutableDirectory: GetModuleFileNameW failed");
			if (length < buffer.size())
				return std::filesystem::path(std::wstring(buffer.data(), length)).parent_path();

			// The path was truncated: retry with a bigger buffer, up to the Windows limit
			if (buffer.size() >= MAX_WINDOWS_PATH)
				throw std::runtime_error("getExecutableDirectory: executable path too long");
			buffer.resize(buffer.size() * 2);
		}
	}

	std::string readTextFile(const std::filesystem::path& path, std::uintmax_t maxSize)
	{
		std::error_code error;
		if (!std::filesystem::is_regular_file(path, error))
			throw std::runtime_error("readTextFile: file not found");

		const std::uintmax_t size = std::filesystem::file_size(path, error);
		if (error)
			throw std::runtime_error("readTextFile: cannot read file size");
		if (size > maxSize)
			throw std::length_error("readTextFile: file too large");

		std::ifstream in(path, std::ios::binary);
		if (!in)
			throw std::runtime_error("readTextFile: cannot open file");

		std::string text(static_cast<size_t>(size), '\0');
		if (size > 0 && !in.read(text.data(), static_cast<std::streamsize>(size)))
			throw std::runtime_error("readTextFile: read failed");
		return text;
	}

	std::vector<uint8_t> readBinaryFile(const std::filesystem::path& path, std::uintmax_t maxSize)
	{
		std::error_code error;
		const std::uintmax_t size = std::filesystem::file_size(path, error);
		if (error)
			throw std::runtime_error("readBinaryFile: cannot read file size");
		if (size > maxSize)
			throw std::length_error("readBinaryFile: file too large");

		std::ifstream in(path, std::ios::binary);
		if (!in)
			throw std::runtime_error("readBinaryFile: cannot open file");

		std::vector<uint8_t> data(static_cast<size_t>(size));
		if (size > 0 && !in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size)))
			throw std::runtime_error("readBinaryFile: read failed");
		return data;
	}
}