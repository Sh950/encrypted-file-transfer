#include "Client.h"
#include "RSAWrapper.h"

#include <chrono>
#include <stdexcept>
#include <iostream>
#include <string>
#include <utility>

namespace
{
	void log(const std::string& message)
	{
		std::cout << "[client] " << message << std::endl;
	}

	using namespace std::chrono_literals;
	constexpr std::chrono::milliseconds NETWORK_TIMEOUT = 30s;

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

	if (!identity_)
		registerNew();

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
		std::cout << "server responded with an error" << std::endl;
	}

	throw std::runtime_error("server responded with an error " + std::to_string(Protocol::MAX_SERVER_ERROR_RETRIES)
		+ " times to request " + codeText(static_cast<uint16_t>(code)) + " (last response " + codeText(lastCode) + ")");
}