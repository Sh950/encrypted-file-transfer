#include "Client.h"
#include "ClientIdentity.h"
#include "FileUtils.h"
#include "SelfTests.h"
#include "TcpConnection.h"
#include "TransferConfig.h"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <utility>

namespace
{
	constexpr const char* SELF_TEST_FLAG = "--self-test";
	constexpr const char* TRANSFER_CONFIG_FILE_NAME = "transfer.json";
}

int main(int argc, char* argv[])
{
	// Development only: client.exe --self-test runs the component tests instead of the client
	if (argc >= 2 && std::string(argv[1]) == SELF_TEST_FLAG)
		return runSelfTests();

	try
	{
		const std::filesystem::path directory = FileUtils::getExecutableDirectory();
		TransferConfig config = loadTransferConfig(directory / TRANSFER_CONFIG_FILE_NAME);
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