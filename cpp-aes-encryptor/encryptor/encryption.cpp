#include "encryptor.h"
#include <filters.h>
#include <aes.h>
#include <hex.h>

//vector/array to SecByteBlock
CryptoPP::SecByteBlock encryptor::vector_to_secbyteblock(const std::vector<uint8_t>& input) {
	return CryptoPP::SecByteBlock(input.data(), input.size());
}

//string to SecByteBlock
CryptoPP::SecByteBlock encryptor::string_to_secbyteblock(const std::string& keyString) {
	std::vector<uint8_t> keyVector(keyString.begin(), keyString.end());
	return vector_to_secbyteblock(keyVector);
}

std::string encryptor::encrypt(const std::string& plainText, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv)
{
    try {
        std::string text;

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        CryptoPP::StringSource(plainText, true,
            new CryptoPP::StreamTransformationFilter(encryptor,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(text),
                    false
                )
            )
        );

        return text;
    }
    catch (const CryptoPP::Exception& e) {
#ifdef _DEBUG
        std::cerr << "Encryption error: \"" << plainText << "\" " << e.what() << "\n";
#else 
        (void)e;
#endif
    }

	return "Failed to encrypt";
}

std::string encryptor::decrypt(const std::string& cipherText, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv)
{
    try {
        std::string text;

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        CryptoPP::StringSource(cipherText, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::StreamTransformationFilter(decryptor,
                    new CryptoPP::StringSink(text)
                )
            )
        );

        return text;
    }
    catch (const CryptoPP::Exception& e) {
#ifdef _DEBUG
        std::cerr << "Decryption error: \"" << cipherText << "\" " << e.what() << "\n";
#else 
        (void)e;
#endif
    }

    return "Failed to decrypt";
}

