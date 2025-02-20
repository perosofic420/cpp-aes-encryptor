#pragma once
#include <modes.h>
#include <string>
#include <vector>

class encryptor
{
public:
	encryptor();
	~encryptor();
private:
	void prompt();
	void prompt_encrypt();
	void prompt_decrypt();

	CryptoPP::SecByteBlock vector_to_secbyteblock(const std::vector<uint8_t>& input);
	CryptoPP::SecByteBlock string_to_secbyteblock(const std::string& keyString);
	std::string encrypt(const std::string& plainText, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv);
	std::string decrypt(const std::string& cipherText, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv);
};

