#include "TransferConfig.h"
#include "FileUtils.h"
#include "Protocol.h"
#include "nlohmann/json.hpp"

#include <limits>
#include <stdexcept>

namespace
{
	constexpr std::uintmax_t MAX_CONFIG_FILE_SIZE = 64 * 1024;
	constexpr size_t         MAX_IP_LENGTH = 253;
	constexpr int64_t        MIN_PORT = 1;
	constexpr int64_t        MAX_PORT = std::numeric_limits<uint16_t>::max();

	std::string getString(const nlohmann::json& object, const char* key)
	{
		if (!object.contains(key) || !object.at(key).is_string())
			throw std::runtime_error(std::string("transfer.json: \"") + key + "\" must be a string");
		return object.at(key).get<std::string>();
	}
}

// Assumes standard JSON: Windows paths must be written with \\ or /.
TransferConfig loadTransferConfig(const std::filesystem::path& path)
{
	const std::string text = FileUtils::readTextFile(path, MAX_CONFIG_FILE_SIZE);

	nlohmann::json root;
	try
	{
		root = nlohmann::json::parse(text);
	}
	catch (const nlohmann::json::parse_error& e)
	{
		throw std::runtime_error(std::string("transfer.json: invalid JSON: ") + e.what());
	}

	if (!root.is_object() || !root.contains("server") || !root.at("server").is_object())
		throw std::runtime_error("transfer.json: \"server\" must be an object");
	const nlohmann::json& server = root.at("server");

	TransferConfig config{};

	config.ip = getString(server, "ip");
	if (config.ip.empty() || config.ip.size() > MAX_IP_LENGTH || !Protocol::isPrintableAscii(config.ip))
		throw std::runtime_error("transfer.json: invalid \"ip\"");

	if (!server.contains("port") || !server.at("port").is_number_integer())
		throw std::runtime_error("transfer.json: \"port\" must be an integer");
	const int64_t port = server.at("port").get<int64_t>();
	if (port < MIN_PORT || port > MAX_PORT)
		throw std::runtime_error("transfer.json: \"port\" must be between 1 and 65535");
	config.port = static_cast<uint16_t>(port);

	config.clientName = getString(server, "client");
	if (!Protocol::isValidClientName(config.clientName))
		throw std::runtime_error("transfer.json: \"client\" must be 1-100 printable ASCII characters");

	if (!root.contains("files") || !root.at("files").is_array() || root.at("files").empty())
		throw std::runtime_error("transfer.json: \"files\" must be a non-empty array");
	for (const nlohmann::json& file : root.at("files"))
	{
		if (!file.is_string() || file.get<std::string>().empty())
			throw std::runtime_error("transfer.json: every entry in \"files\" must be a non-empty string");
		const std::string pathText = file.get<std::string>();
		// UTF-8 so that non-ASCII directory names are decoded correctly on Windows
		config.files.emplace_back(std::u8string(pathText.begin(), pathText.end()));
	}

	return config;
}