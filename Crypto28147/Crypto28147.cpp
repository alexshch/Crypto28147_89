#include "Crypto28147.h"
#include "IncorrectInputDataExeption.h"

Crypto28147SimpleReplacement::Crypto28147SimpleReplacement(std::string key)
{
	try
	{
		if (key.length() != 32)
			throw new IncorrectInputDataExeption();
		memset(secretKey, 0x0, sizeof(secretKey));
		str2key(key, secretKey);

		unsigned short int testSBoxCryptoProA[8][16] = {{0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5},
														{0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1},
														{0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9},
														{0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6},
														{0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6},
														{0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6},
														{0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE},
														{0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4}
		}; 

		blockSize = 8;
		
		memcpy(SBoxCryptoProA,testSBoxCryptoProA,sizeof(testSBoxCryptoProA));
	}
	catch (IncorrectInputDataExeption* e)
	{
		std::cout << "The key length is not equally 32 bytes\n";
	}
}


unsigned __int32 Crypto28147SimpleReplacement::addMod32(const unsigned __int32 arg1, const unsigned __int32 arg2) 
{
	if ((arg1 + arg2) < ULONG_MAX )
	{
		return (arg1 + arg2);
	}
	else 
	{
		return ((arg1 + arg2) - ULONG_MAX);
	}
}

// выделение старшей и младшей части из 64 битного числа
void Crypto28147SimpleReplacement::separeteDataBlock(const unsigned __int64 dataBlock, unsigned __int32& N1, unsigned __int32& N2)
{
	N1 =  dataBlock & 0x00000000FFFFFFFF;          // 
	N2 =  (dataBlock >> 32) & 0x00000000FFFFFFFF;  // 
}

// объединение двух чисел по 32 бита в одно 64 битное
unsigned __int64 Crypto28147SimpleReplacement::mergeToDataBlock(const unsigned __int32 N1, const unsigned __int32 N2)
{
	unsigned __int64 temp = N2;
	return  N1 | (temp<<32);		
}

//главный шаг криптопреобразования
unsigned __int64 Crypto28147SimpleReplacement::mainCryptoStep(const unsigned __int64 dataChunk, const unsigned __int32 keyChunk, bool esp = false)
{	
	unsigned __int32 N1 = 0x0;
	unsigned __int32 N2 = 0x0;
	unsigned __int32 temp;
	unsigned __int64 retVal;	

	// step0
	separeteDataBlock(dataChunk, N1, N2);	
	// step1	
	temp = addMod32(N1, keyChunk);	
	// step2	
	temp = boxSubstitution(temp);	
	// step3
	temp = cycleShift11Left(temp);
	// steo4
	temp ^= N2;
	// step5
	if (esp)
	{
		N2 = temp;
	}
	else
	{
		N2 = N1;
		N1 = temp;				
	}	
	// step6
	retVal = mergeToDataBlock(N1, N2);
	return retVal;
}

void Crypto28147SimpleReplacement::encrypt(const std::string input, std::string& output)
{	
	try
	{	
		if (input.length() % 8 != 0)
		{		
			throw new IncorrectInputDataExeption();
		}
		int blocksNumber = input.size() / blockSize;
		std::string substring;
		unsigned __int64 dataChunkRaw;
		unsigned __int64 dataChunkEncrypted;
		for(int i = 0; i < blocksNumber; i++)
		{
			substring = input.substr(i*blockSize, blockSize);
			dataChunkRaw = str2data(substring);
			dataChunkEncrypted = oneBlockEncrypt(dataChunkRaw);
			//output += data2str(dataChunkEncrypted);
			rawData.push_back(dataChunkEncrypted);
		}

		for (std::vector<unsigned __int64>::iterator it = rawData.begin() ; it != rawData.end(); it++)
		{
			output += data2str(*it);
		}
		rawData.clear();
	}
	catch (IncorrectInputDataExeption* e)
	{		

		std::cout << "Encrypted data is not divide by 8 bytes\n";	
	}
}
void Crypto28147SimpleReplacement::decrypt(const std::string input, std::string& output)
{
	try
	{		
		if (input.length() % 8 != 0)
		{			
			throw new IncorrectInputDataExeption();
		}
		int blocksNumber = input.length() / blockSize;
		std::string substring;
		unsigned __int64 dataChunkRaw;
		unsigned __int64 dataChunkDecrypted;
		for(int i = 0; i < blocksNumber; i++)
		{
			substring = input.substr(i*blockSize, blockSize);
			dataChunkRaw = str2data(substring);
			dataChunkDecrypted = oneBlockDecrypt(dataChunkRaw);
			//output += data2str(dataChunkDecrypted);
			rawData.push_back(dataChunkDecrypted);
		}

		for (std::vector<unsigned __int64>::iterator it = rawData.begin() ; it != rawData.end(); it++)
		{
			output += data2str(*it);
		}
		rawData.clear();
	}
	catch (IncorrectInputDataExeption* e)
	{		
		std::cout << "Decrypted data is not divide by 8 bytes\n";	
	}
}

// подстановка из таблицы замен
unsigned __int32 Crypto28147SimpleReplacement::boxSubstitution(const unsigned __int32 number)
{
	unsigned __int32 acum = 0;
	unsigned __int8 temp;

	for (int i = 0; i < 8; i++)
	{
		temp = (number >> 4*i) & 0x0000000F;
		temp = SBoxCryptoProA[i][temp];
		acum |= (temp << i*4);	
	}
	return acum;
}

// подитовый сдвиг влево на 11 бит
unsigned __int32 Crypto28147SimpleReplacement::cycleShift11Left(const unsigned __int32 number)
{	
	return ((number >> 21) | (number << 11));
}

// шифрование 
unsigned __int64 Crypto28147SimpleReplacement::oneBlockEncrypt(unsigned __int64 data)
{
	bool flag = false;

	for (int i = 0; i < 3; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			data = mainCryptoStep(data, secretKey[j],flag);
		}
	}
	
	for (int j = 7; j >= 0; j--){
		if (j == 0)
			flag = true; 
		data = mainCryptoStep(data, secretKey[j], flag);
	}
	return data;
}

unsigned __int64	Crypto28147SimpleReplacement::oneBlockDecrypt(unsigned __int64 data)
{
	bool flag = false;
	for (int j = 0; j < 8; j++)
	{
		data = mainCryptoStep(data, secretKey[j],flag);
	}
	
	for (int i = 0; i < 3; i++)
	{
		for (int j = 7; j >= 0; j--)
		{
			if (i == 2 && j == 0)
				flag = true;
			data = mainCryptoStep(data, secretKey[j], flag);
		}
	}
	return data;
}


void Crypto28147SimpleReplacement::str2key(const std::string inputKeyStr, unsigned __int32* key)
{
	for (int i = 0; i < 32; i++)
		key[7 - (i / 4)] |= (unsigned int) inputKeyStr[i] << (8 * (3 - i % 4));
}


unsigned __int64 Crypto28147SimpleReplacement::str2data(const std::string inputStr)
{
	unsigned __int64 retVal = 0;
	unsigned __int64 temp = 0;
	for (int i = 0; i < blockSize; i++)
	{
		temp = (unsigned __int64) inputStr[i] & 0x00000000000000FF;
		retVal |= (temp << (blockSize*i));
	}
	return retVal;
}

std::string	Crypto28147SimpleReplacement::data2str(const unsigned __int64 data)
{
	std::string retVal;
	unsigned char tmp; 
	for (int i = 0; i < blockSize; i++)	
	{
		tmp =  unsigned char (data >> (blockSize*i) & 0x00000000000000FF); 
		retVal.push_back(tmp);
	}
	return retVal;

}
