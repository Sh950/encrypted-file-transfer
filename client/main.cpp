#include "Client.h"
#include "ClientIdentity.h"
#include "FileUtils.h"
#include "TcpConnection.h"
#include "TransferConfig.h"

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <optional>
#include <utility>

namespace
{
	constexpr const char* TRANSFER_CONFIG_FILE_NAME = "transfer.json";
}

// Batch mode: no input from the user; everything comes from files in the exe directory
int main()
{
	try
	{
		const std::filesystem::path directory = FileUtils::getExecutableDirectory();
		TransferConfig config = loadTransferConfig(directory / TRANSFER_CONFIG_FILE_NAME);

		// A corrupted me.info throws: an existing client must not register again
		std::optional<ClientIdentity> identity = loadIdentity(directory);

		WinsockSession winsock;
		Client client(std::move(config), std::move(identity), directory);
		return client.run() ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	catch (const std::exception& e)
	{
		std::cerr << "Fatal: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
	catch (...)
	{
		std::cerr << "Fatal: unknown error" << std::endl;
		return EXIT_FAILURE;
	}
}