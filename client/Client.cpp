#include "Client.h"

#include <iostream>
#include <string>
#include <utility>

namespace
{
	void log(const std::string& message)
	{
		std::cout << "[client] " << message << std::endl;
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

	return true;
}