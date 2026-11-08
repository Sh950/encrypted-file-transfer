#include "Client.h"
#include "AESWrapper.h"
#include "Cksum.h"
#include "FileUtils.h"
#include "RSAWrapper.h"

#include <cryptlib.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace
{
	void log(const std::string& message)
	{
		std::cout << "[client] " << message << std::endl;
	}

	// Exact wording required by the assignment
	void reportServerError()
	{
		std::cout << "server responded with an error" << std::endl;
	}

	using namespace std::chrono_literals;
	constexpr std::chrono::milliseconds NETWORK_TIMEOUT = 30s;
	constexpr size_t PACKET_SIZE = 64 * 1024;
	constexpr size_t AES_BLOCK_SIZE = 16;
	constexpr size_t MAX_ENCRYPTED_SIZE = std::min<size_t>(
		std::numeric_limits<uint32_t>::max(),                                     // Content Size is 4 bytes
		static_cast<size_t>(std::numeric_limits<uint16_t>::max()) * PACKET_SIZE); // Total packets is 2 bytes

	// PKCS#7 padding adds 1..16 bytes, so the original must leave room for a full block
	constexpr size_t MAX_ORIGINAL_SIZE = MAX_ENCRYPTED_SIZE - AES_BLOCK_SIZE;

	std::string codeText(uint16_t code)
	{
		return std::to_string(code);
	}
}

Client::Client(TransferConfig config, std::optional<ClientIdentity> identity, std::filesystem::path directory)
	: config_(std::move(config)), identity_(std::move(identity)), directory_(std::move(directory))
{}

bool Client::run()
{
	log("server " + config_.ip + ":" + std::to_string(config_.port) + ", client \"" + config_.clientName + "\", "
		+ std::to_string(config_.files.size()) + " file(s)");

	if (identity_)
		log("found me.info - registered as \"" + identity_->name + "\", will reconnect");
	else
		log("no me.info - will register as a new client");

	connect();

	// A denied reconnect clears the identity, so the client falls through to registration
	if (identity_ && !reconnect())
		log("continuing as a new client");

	if (!identity_)
	{
		registerNew();
		sendPublicKey();
	}

	int verified = 0;
	int crcFailed = 0;
	int skipped = 0;
	for (const std::filesystem::path& path : config_.files)
	{
		switch (sendFile(path))
		{
		case FileResult::Verified:  ++verified;  break;
		case FileResult::CrcFailed: ++crcFailed; break;
		case FileResult::Skipped:   ++skipped;   break;
		}
	}

	log("done: " + std::to_string(verified) + " verified, " + std::to_string(crcFailed) + " failed CRC, "
		+ std::to_string(skipped) + " skipped");
	return crcFailed == 0 && skipped == 0;
}

void Client::connect()
{
	connection_.emplace(config_.ip, config_.port, NETWORK_TIMEOUT);
	log("connected to " + config_.ip + ":" + std::to_string(config_.port));
}

Protocol::ClientId Client::currentClientId() const
{
	// Before registration there is no ID yet; the server ignores the field in a register request
	return identity_ ? identity_->id : Protocol::ClientId{};
}

void Client::sendRequest(Protocol::RequestCode code, const std::vector<uint8_t>& payload)
{
	connection_->sendAll(Protocol::buildRequest(currentClientId(), code, payload));
}

// A malformed header throws: after it the stream position is unknown, so the connection cannot be reused.
Client::Response Client::receiveResponse()
{
	const Protocol::ResponseHeader header =
		Protocol::parseResponseHeader(connection_->recvExact(Protocol::RESPONSE_HEADER_SIZE));
	Response response{ header.code, connection_->recvExact(header.payloadSize) };
	log("received " + codeText(static_cast<uint16_t>(response.code)));
	return response;
}

// Sends a request and waits for one of the expected (successful) responses.
// Any other well-formed response is a server error: the same request is sent again, up to 3 times.
Client::Response Client::exchange(Protocol::RequestCode code, const std::vector<uint8_t>& payload,
	std::initializer_list<Protocol::ResponseCode> expected)
{
	uint16_t lastCode = 0;
	for (int attempt = 1; attempt <= Protocol::MAX_SERVER_ERROR_RETRIES; ++attempt)
	{
		log("sending " + codeText(static_cast<uint16_t>(code)));
		sendRequest(code, payload);
		Response response = receiveResponse();

		for (Protocol::ResponseCode accepted : expected)
		{
			if (response.code == accepted)
				return response;
		}

		lastCode = static_cast<uint16_t>(response.code);
		reportServerError();
	}

	throw std::runtime_error("server responded with an error " + std::to_string(Protocol::MAX_SERVER_ERROR_RETRIES)
		+ " times to request " + codeText(static_cast<uint16_t>(code)) + " (last response " + codeText(lastCode) + ")");
}

// Returns true if the server accepted the reconnect (1605) and sent an AES key.
// Returns false on 1606: the server does not know this client, so the old identity is deleted.
bool Client::reconnect()
{
	if (identity_->name != config_.clientName)
		log("warning: transfer.json says \"" + config_.clientName + "\", but this client is registered as \""
			+ identity_->name + "\" - reconnecting with the registered name");

	log("reconnecting as \"" + identity_->name + "\"");
	const Response response = exchange(Protocol::RequestCode::Reconnect, Protocol::makeNameField(identity_->name),
		{ Protocol::ResponseCode::ReconnectOk, Protocol::ResponseCode::ReconnectDenied });

	if (response.code == Protocol::ResponseCode::ReconnectDenied)
	{
		if (Protocol::parseClientIdPayload(response.payload) != identity_->id)
			throw std::runtime_error("the server denied the reconnect for a different client ID");
		log("reconnect denied - the server does not know this client; registering again");
		deleteIdentity(directory_);
		identity_.reset();
		return false;
	}

	setAesKeyFromResponse(response);
	return true;
}

void Client::registerNew()
{
	log("registering as \"" + config_.clientName + "\"");
	const Response response = exchange(Protocol::RequestCode::Register,
		Protocol::makeNameField(config_.clientName), { Protocol::ResponseCode::RegisterOk });

	const Protocol::ClientId newId = Protocol::parseClientIdPayload(response.payload);
	// All zeros is what the client sends before it has an ID; the server must never assign it
	if (newId == Protocol::ClientId{})
		throw std::runtime_error("server assigned an all-zero client ID");

	// The key pair is created only after the server accepted the name
	const RSAPrivateWrapper rsa;
	identity_ = ClientIdentity{ config_.clientName, newId, rsa.getPrivateKey() };

	// Saved before the key exchange: if the client stops after this point, the next run reconnects
	saveIdentity(directory_, *identity_);
	log("registered, saved me.info and priv.key");
}

void Client::sendPublicKey()
{
	const RSAPrivateWrapper rsa(identity_->privateKey);
	log("sending public key");
	const Response response = exchange(Protocol::RequestCode::SendPublicKey,
		Protocol::makePublicKeyPayload(identity_->name, rsa.getPublicKey()), { Protocol::ResponseCode::AesKey });
	setAesKeyFromResponse(response);
}

// 1602 and 1605 carry the same payload: the client ID and the AES key encrypted with our public key
void Client::setAesKeyFromResponse(const Response& response)
{
	const Protocol::AesKeyResponse parsed = Protocol::parseAesKeyPayload(response.payload);
	if (parsed.clientId != identity_->id)
		throw std::runtime_error("the server sent an AES key for a different client ID");

	RSAPrivateWrapper rsa(identity_->privateKey);
	std::string aesKey;
	try
	{
		aesKey = rsa.decrypt(parsed.encryptedAesKey);
	}
	catch (const CryptoPP::Exception&)
	{
		throw std::runtime_error("cannot decrypt the AES key - it was not encrypted with this client's public key");
	}

	if (aesKey.size() != Protocol::AES_KEY_SIZE)
		throw std::runtime_error("the decrypted AES key is " + std::to_string(aesKey.size())
			+ " bytes, expected " + std::to_string(Protocol::AES_KEY_SIZE));

	aesKey_.assign(aesKey.begin(), aesKey.end());
	log("key exchange complete");
}

Client::FileResult Client::sendFile(const std::filesystem::path& path)
{
	const std::optional<PreparedFile> file = prepareFile(path);
	if (!file)
		return FileResult::Skipped;

	const std::vector<uint8_t> nameField = Protocol::makeNameField(file->name);
	int attempt = 1;
	int serverErrors = 0;
	while (true)
	{
		log(file->name + ": attempt " + std::to_string(attempt) + " of " + std::to_string(Protocol::MAX_FILE_SEND_ATTEMPTS));
		sendPackets(*file);
		const Response response = receiveResponse();

		// A 1607, or a 1603 that does not describe this file, is a server error: resend without counting a CRC attempt
		bool valid = response.code == Protocol::ResponseCode::FileReceived;
		Protocol::FileReceivedResponse received{};
		if (valid)
		{
			received = Protocol::parseFileReceivedPayload(response.payload);
			valid = received.clientId == identity_->id && received.fileName == file->name
				&& received.contentSize == file->encrypted.size();
		}
		if (!valid)
		{
			reportServerError();
			if (++serverErrors >= Protocol::MAX_SERVER_ERROR_RETRIES)
				throw std::runtime_error("server responded with an error " + std::to_string(Protocol::MAX_SERVER_ERROR_RETRIES)
					+ " times while receiving " + file->name);
			continue;
		}

		if (received.cksum == file->cksum)
		{
			log(file->name + ": CRC verified by the server");
			exchange(Protocol::RequestCode::CrcOk, nameField, { Protocol::ResponseCode::Ack });
			return FileResult::Verified;
		}

		log(file->name + ": CRC mismatch (server " + std::to_string(received.cksum)
			+ ", client " + std::to_string(file->cksum) + ")");
		if (attempt < Protocol::MAX_FILE_SEND_ATTEMPTS)
		{
			// 901 has no response: the packets are sent again right away
			sendRequest(Protocol::RequestCode::CrcRetry, nameField);
			++attempt;
			continue;
		}

		exchange(Protocol::RequestCode::CrcAbort, nameField, { Protocol::ResponseCode::Ack });
		log(file->name + ": giving up after " + std::to_string(attempt) + " attempts");
		return FileResult::CrcFailed;
	}
}

// Checks, reads, checksums and encrypts one file. Returns nullopt (after logging why) if the file must be skipped.
std::optional<Client::PreparedFile> Client::prepareFile(const std::filesystem::path& path)
{
	std::error_code error;
	if (!std::filesystem::is_regular_file(path, error))
	{
		log("skipping a file that does not exist or is not a regular file");
		return std::nullopt;
	}

	// The protocol sends the file name only, in ASCII
	const std::u8string utf8Name = path.filename().u8string();
	const std::string name(utf8Name.begin(), utf8Name.end());
	try
	{
		Protocol::makeNameField(name);
	}
	catch (const std::exception&)
	{
		log("skipping a file whose name is not 1-254 printable ASCII characters");
		return std::nullopt;
	}

	const std::uintmax_t size = std::filesystem::file_size(path, error);
	if (error || size > MAX_ORIGINAL_SIZE)
	{
		log("skipping " + name + ": too large for the protocol's 4-byte size and 2-byte packet count");
		return std::nullopt;
	}

	const std::vector<uint8_t> content = FileUtils::readBinaryFile(path, MAX_ORIGINAL_SIZE);

	AESWrapper aes(aesKey_.data(), static_cast<unsigned int>(aesKey_.size()));
	const std::string cipher = aes.encrypt(reinterpret_cast<const char*>(content.data()),
		static_cast<unsigned int>(content.size()));

	PreparedFile file{};
	file.name = name;
	file.encrypted.assign(cipher.begin(), cipher.end());
	file.origSize = static_cast<uint32_t>(content.size());
	file.cksum = Cksum::computeCksum(content);
	log(name + ": " + std::to_string(file.origSize) + " bytes, CRC " + std::to_string(file.cksum)
		+ ", " + std::to_string(file.encrypted.size()) + " bytes encrypted");
	return file;
}

// Sends the whole encrypted file as numbered 828 packets (1..total). The server answers only after the last one.
void Client::sendPackets(const PreparedFile& file)
{
	const size_t total = (file.encrypted.size() + PACKET_SIZE - 1) / PACKET_SIZE;
	const uint32_t contentSize = static_cast<uint32_t>(file.encrypted.size());

	for (size_t index = 0; index < total; ++index)
	{
		const size_t offset = index * PACKET_SIZE;
		const size_t length = std::min(PACKET_SIZE, file.encrypted.size() - offset);
		const std::vector<uint8_t> chunk(file.encrypted.begin() + offset, file.encrypted.begin() + offset + length);

		sendRequest(Protocol::RequestCode::SendFile, Protocol::makeFilePacketPayload(contentSize, file.origSize,
			static_cast<uint16_t>(index + 1), static_cast<uint16_t>(total), file.name, chunk));
	}
	log(file.name + ": sent " + std::to_string(total) + " packet(s)");
}