#pragma once
#include <string>
class CryptoBase
{
public:
	virtual void encrypt(const std::string, std::string&) = 0;
	virtual void decrypt(const std::string, std::string&) = 0;
};