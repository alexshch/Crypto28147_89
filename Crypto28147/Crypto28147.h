#pragma once

#include "CryptoBase.h"
#include <limits>
#include <iostream>
#include <vector>
#include <iterator>

class Crypto28147SimpleReplacement: public CryptoBase
{
public: 

	void encrypt(const std::string input, std::string& output);
	void decrypt(const std::string input, std::string& output);
	Crypto28147SimpleReplacement(std::string key);	

protected:
	unsigned __int8 blockSize;
	unsigned short int SBoxCryptoProA[8][16]; 
	unsigned __int32	secretKey[8];
	std::vector<unsigned __int64> rawData;
	unsigned __int32	addMod32(const unsigned __int32 arg1, const unsigned __int32 arg2);
	void				separeteDataBlock(const unsigned __int64 dataBlock, unsigned __int32& N1, unsigned __int32& N2);
	unsigned __int64	mergeToDataBlock(const unsigned __int32 N1, const unsigned __int32 N2);
	unsigned __int64	mainCryptoStep(const unsigned __int64 dataChunk, const unsigned __int32 keyChunk, bool esp);
	unsigned __int32	boxSubstitution(const unsigned __int32 number);
	unsigned __int32	cycleShift11Left(const unsigned __int32 number);
	unsigned __int64	oneBlockEncrypt(unsigned __int64);
	unsigned __int64	oneBlockDecrypt(unsigned __int64);
	void				str2key(const std::string, unsigned __int32* key);
	unsigned __int64    str2data(const std::string inputStr);
	std::string			data2str(const unsigned __int64);	
};

