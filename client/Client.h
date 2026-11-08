#pragma once

#include "ClientIdentity.h"
#include "Protocol.h"
#include "TcpConnection.h"
#include "TransferConfig.h"

#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <vector>
#include <string>

// Runs the whole protocol: connect, identify (register or reconnect), send every file.
class Client
{
public:
	enum class FileResult { Verified, CrcFailed, Skipped };
	Client(TransferConfig config, std::optional<ClientIdentity> identity, std::filesystem::path directory);
	~Client();
	Client(const Client&) = delete;
	Client& operator=(const Client&) = delete;

	// Returns true only if every file was transferred and its CRC verified
	bool run();

private:
	struct Response
	{
		Protocol::ResponseCode code;
		std::vector<uint8_t>   payload;
	};

	struct PreparedFile
	{
		std::string          name;		// file name only, sent in the protocol
		std::vector<uint8_t> encrypted;
		uint32_t             origSize;
		uint32_t             cksum;		// of the original content
	};

	void connect();
	void sendRequest(Protocol::RequestCode code, const std::vector<uint8_t>& payload);
	Response receiveResponse();
	Response exchange(Protocol::RequestCode code, const std::vector<uint8_t>& payload,
		std::initializer_list<Protocol::ResponseCode> expected);
	Protocol::ClientId currentClientId() const;
	void registerNew();
	void sendPublicKey();
	void setAesKeyFromResponse(const Response& response);
	bool reconnect();

	TransferConfig config_;
	std::optional<ClientIdentity> identity_;
	std::filesystem::path directory_;
	std::optional<TcpConnection> connection_;
	std::vector<uint8_t> aesKey_;	// received from the server; empty until the key 
	FileResult sendFile(const std::filesystem::path& path);
	std::optional<PreparedFile> prepareFile(const std::filesystem::path& path);
	void sendPackets(const PreparedFile& file);
};