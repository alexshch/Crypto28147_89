/*---------------------------------------------------------------------------
 *  Author:        Alexander Shcherbakov
 *  Written:       14/09/2015
 *  Last updated:  15/09/20015
 *  
 *  Execution:     
 *	Decrypt data:  Crypto28147.exe -decr < encrypted.txt > decrypted.txt 
 *  Encrypt data:  Crypto28147.exe -encr < data.txt > encrypted.txt  
 *
 *	Программа реализует    шифрование и расшифрование данных, полученных из 
 *  стандатного  *  потока ввода по алгиритсму простой замены ГОСТ 28147-89. 
 *	Размер входных данных должен быть кратен 8
 *--------------------------------------------------------------------------*/

#include <iostream>
#include <istream>
#include <ostream>
#include <iterator>
#include "Crypto28147.h"


int main(int argc, char* argv[]) 
{ 
	const std::string testKey = "abcdfgteqsdfrtedfsretkdpbdltesas";
	Crypto28147SimpleReplacement crp(testKey);
	
	std::string encrypted;
	std::string decrypted;	

	if (argc > 1)
	{	
		if (0 == strcmp(argv[1], "-encr"))
		{				 
			std::cin >> std::noskipws;			
			std::istream_iterator<char> it(std::cin);
			std::istream_iterator<char> end;
			std::string inputLine(it, end);
			crp.encrypt(inputLine, encrypted);			
			std::cout << encrypted << std::endl;
		}
		else if (0 == strcmp(argv[1], "-decr"))
		{
			std::string inputLine;
			while (std::getline(std::cin, inputLine))
			{					
				crp.decrypt(inputLine, decrypted);
				std::cout << decrypted << std::endl;				
			}
		}
		else if (0 == strcmp(argv[1], "-deGamma"))
		{
			std::string inputLine;
			while (std::getline(std::cin, inputLine))
			{
				crp.encryptGamming(inputLine, decrypted);
				std::cout << decrypted << std::endl;
			}
		}
		else if (0 == strcmp(argv[1], "-deGammaFb"))
		{
			std::string inputLine;
			while (std::getline(std::cin, inputLine))
			{
				crp.encryptGammingFeedback(inputLine, decrypted);
				std::cout << decrypted << std::endl;
			}
		}
		else
		{
			std::cout << "Unknown cmd args\n";
		}
	}
	else
	{
		std::cout << "no args\n";
	}		 
	return 0; 
}