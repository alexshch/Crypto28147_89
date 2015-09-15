#pragma once
#include <exception>

class IncorrectInputDataExeption : public std::exception
{
	virtual const char* what() const throw()
	{
		return "Crypto28147 errors";
	}
};