#include "encryptor.h"
#include <iostream>

encryptor::encryptor() {
	std::cout << "Welcome to the CPP-AES-Encryptor\n" <<
		"https://github.com/perosofic420/cpp-aes-encryptor\n";

	prompt();
}

encryptor::~encryptor() {

}

void encryptor::prompt() {
	std::cout << "Do you want to encrypt (1) or decrypt (2)?: ";

	std::string type;
	std::cin >> type;

	if (type == "1") {
		prompt_encrypt();
	}
	else if (type == "2") {
		prompt_decrypt();
	}
	else {
		std::cout << "Unknown type.\n";
		prompt();
	}
}

void encryptor::prompt_encrypt() {
	std::cout << "Enter the string you want to encrypt: ";
	std::string text;
	std::cin >> text;

	std::cout << "Enter the key (16, 24 or 32 characters long): ";
	std::string key;
	std::cin >> key;

	int key_size = key.size();
	if (key_size != 16 && key_size != 24 && key_size != 32) {
		std::cout << "Incorrect key length.\n";
		prompt_encrypt();
	}

	std::cout << "Enter the IV (16 characters long): ";
	std::string iv;
	std::cin >> iv;

	if (iv.size() != 16) {
		std::cout << "Incorrect IV length.\n";
		prompt_encrypt();
	}

	CryptoPP::SecByteBlock key_sbb = string_to_secbyteblock(key);
	CryptoPP::SecByteBlock iv_sbb = string_to_secbyteblock(iv);

	std::string encrypted = encrypt(text, key_sbb, iv_sbb);
	std::cout << "Encrypted text: '" << encrypted << "'\n";

	prompt();
}

void encryptor::prompt_decrypt() {
	std::cout << "Enter the string you want to decrypt: ";

	std::string text;
	std::cin >> text;

	std::cout << "Enter the key (16, 24 or 32 characters long): ";
	std::string key;
	std::cin >> key;

	int key_size = key.size();
	if (key_size != 16 && key_size != 24 && key_size != 32) {
		std::cout << "Incorrect key length.\n";
		prompt_decrypt();
	}

	std::cout << "Enter the IV (16 characters long): ";
	std::string iv;
	std::cin >> iv;

	if (iv.size() != 16) {
		std::cout << "Incorrect IV length.\n";
		prompt_decrypt();
	}

	CryptoPP::SecByteBlock key_sbb = string_to_secbyteblock(key);
	CryptoPP::SecByteBlock iv_sbb = string_to_secbyteblock(iv);

	std::string decrypted = decrypt(text, key_sbb, iv_sbb);
	std::cout << "Decrypted text: '" << decrypted << "'\n";

	prompt();
}
