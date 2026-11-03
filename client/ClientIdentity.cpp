#include "ClientIdentity.h"
#include "FileUtils.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"

#include <fstream>
#include <stdexcept>
#include <vector>


namespace
{
	constexpr const char* ME_INFO_FILE_NAME = "me.info";
	constexpr const char* PRIV_KEY_FILE_NAME = "priv.key";
	constexpr size_t         ME_INFO_LINE_COUNT = 3;
	constexpr std::uintmax_t MAX_IDENTITY_FILE_SIZE = 4096;
	constexpr size_t  HEX_CHARS_PER_BYTE = 2;
	constexpr int     NIBBLE_BITS = 4;

	[[noreturn]] void throwCorrupted(const std::string& reason)
	{
		throw std::runtime_error("me.info/priv.key corrupted: " + reason
			+ ". Delete both files to register as a new client.");
	}
	
	std::vector<std::string> splitLines(const std::string& text)
	{
		std::vector<std::string> lines;
		std::string current;
		for (char c : text)
		{
			if (c == '\n')
			{
				if (!current.empty() && current.back() == '\r')
					current.pop_back();
				lines.push_back(current);
				current.clear();
			}
			else
			{
				current += c;
			}
		}
		// Last line without a trailing newline
		if (!current.empty())
			lines.push_back(current);
		return lines;
	}

	std::optional<uint8_t> hexDigitValue(char c)
	{
		if (c >= '0' && c <= '9')
			return static_cast<uint8_t>(c - '0');
		if (c >= 'a' && c <= 'f')
			return static_cast<uint8_t>(c - 'a' + 10);
		if (c >= 'A' && c <= 'F')
			return static_cast<uint8_t>(c - 'A' + 10);
		return std::nullopt;
	}
	
	std::optional<Protocol::ClientId> hexToClientId(const std::string& hex)
	{
		if (hex.size() != Protocol::CLIENT_ID_SIZE * HEX_CHARS_PER_BYTE)
			return std::nullopt;

		Protocol::ClientId id{};
		for (size_t i = 0; i < id.size(); ++i)
		{
			const std::optional<uint8_t> high = hexDigitValue(hex[i * HEX_CHARS_PER_BYTE]);
			const std::optional<uint8_t> low = hexDigitValue(hex[i * HEX_CHARS_PER_BYTE + 1]);
			if (!high || !low)
				return std::nullopt;
			id[i] = static_cast<uint8_t>((*high << NIBBLE_BITS) | *low);
		}
		return id;
	}

	std::string clientIdToHex(const Protocol::ClientId& id)
	{
		constexpr char HEX_DIGITS[] = "0123456789abcdef";
		constexpr uint8_t LOW_NIBBLE_MASK = 0x0F;

		std::string hex;
		hex.reserve(id.size() * HEX_CHARS_PER_BYTE);
		for (uint8_t byte : id)
		{
			hex += HEX_DIGITS[byte >> NIBBLE_BITS];
			hex += HEX_DIGITS[byte & LOW_NIBBLE_MASK];
		}
		return hex;
	}

	void writeFileAtomically(const std::filesystem::path& path, const std::string& content)
	{
		std::filesystem::path tempPath = path;
		tempPath += ".tmp";

		{
			std::ofstream out(tempPath, std::ios::binary | std::ios::trunc);
			if (!out)
				throw std::runtime_error("cannot create " + tempPath.filename().string());
			out.write(content.data(), static_cast<std::streamsize>(content.size()));
			out.flush();
			if (!out)
				throw std::runtime_error("cannot write " + tempPath.filename().string());
		}	// the file is closed here, before the rename

		// Replaces the existing file in one step: readers see the old file or the new one, not half of it
		std::error_code error;
		std::filesystem::rename(tempPath, path, error);
		if (error)
		{
			std::filesystem::remove(tempPath, error);
			throw std::runtime_error("cannot replace " + path.filename().string());
		}
	}	
}

std::optional<ClientIdentity> loadIdentity(const std::filesystem::path& directory)
{
	const std::filesystem::path meInfoPath = directory / ME_INFO_FILE_NAME;
	const std::filesystem::path privKeyPath = directory / PRIV_KEY_FILE_NAME;

	// No me.info: first run, the client will register
	if (!std::filesystem::exists(meInfoPath))
		return std::nullopt;

	const std::string meInfoText = FileUtils::readTextFile(meInfoPath, MAX_IDENTITY_FILE_SIZE);
	const std::vector<std::string> lines = splitLines(meInfoText);
	if (lines.size() != ME_INFO_LINE_COUNT)
		throwCorrupted("me.info must have exactly 3 lines (name, UUID, private key)");

	const std::string& name = lines[0];
	if (!Protocol::isValidClientName(name))
		throwCorrupted("invalid client name in me.info");

	const std::optional<Protocol::ClientId> id = hexToClientId(lines[1]);
	if (!id)
		throwCorrupted("invalid UUID on line 2 (expected 32 hex characters)");

	// The assignment loads the key from priv.key; it must match line 3 of me.info
	if (!std::filesystem::exists(privKeyPath))
		throwCorrupted("priv.key is missing");

	const std::vector<std::string> keyLines = splitLines(FileUtils::readTextFile(privKeyPath, MAX_IDENTITY_FILE_SIZE));
	if (keyLines.size() != 1)
		throwCorrupted("priv.key must contain exactly one line");

	const std::string& base64Key = keyLines[0];
	if (base64Key != lines[2])
		throwCorrupted("priv.key does not match line 3 of me.info");

	const std::string privateKey = Base64Wrapper::decode(base64Key);
	try
	{
		RSAPrivateWrapper keyCheck(privateKey);
	}
	catch (const CryptoPP::Exception&)
	{
		throwCorrupted("the private key in priv.key cannot be loaded");
	}

	return ClientIdentity{ name, *id, privateKey };
}

void saveIdentity(const std::filesystem::path& directory, const ClientIdentity& identity)
{
	if (!Protocol::isValidClientName(identity.name))
		throw std::invalid_argument("saveIdentity: invalid client name");
	if (identity.privateKey.empty())
		throw std::invalid_argument("saveIdentity: empty private key");

	const std::string base64Key = Base64Wrapper::encode(identity.privateKey);

	// priv.key first: me.info marks the client as registered, so it may only exist once the key is on disk
	writeFileAtomically(directory / PRIV_KEY_FILE_NAME, base64Key + "\n");
	writeFileAtomically(directory / ME_INFO_FILE_NAME,
		identity.name + "\n" + clientIdToHex(identity.id) + "\n" + base64Key + "\n");
}

void deleteIdentity(const std::filesystem::path& directory)
{
	// me.info first: once it is gone the client counts as new, even if removing priv.key then fails
	std::error_code error;
	std::filesystem::remove(directory / ME_INFO_FILE_NAME, error);
	if (error)
		throw std::runtime_error("deleteIdentity: cannot delete me.info");

	std::filesystem::remove(directory / PRIV_KEY_FILE_NAME, error);
	if (error)
		throw std::runtime_error("deleteIdentity: cannot delete priv.key");
}

