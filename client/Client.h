#pragma once

#include "ClientIdentity.h"
#include "TransferConfig.h"

#include <filesystem>
#include <optional>

// Runs the whole protocol: connect, identify (register or reconnect), send every file.
class Client
{
public:
	Client(TransferConfig config, std::optional<ClientIdentity> identity, std::filesystem::path directory);

	Client(const Client&) = delete;
	Client& operator=(const Client&) = delete;

	// Returns true only if every file was transferred and its CRC verified
	bool run();

private:
	TransferConfig config_;
	std::optional<ClientIdentity> identity_;
	std::filesystem::path directory_;
};