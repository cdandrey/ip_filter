#include <iostream>
#include "ip_filter.h"

int main(int, char **)
{
	try
	{	
		ipf::ip_pool_t ip_pool;

		for (std::string line; std::getline(std::cin, line);)
		{
			auto ip_str = line.substr(0, line.find_first_of('\t'));
			ip_pool.insert({ ipf::get_key(ip_str,'.'),ip_str });
		}

		ipf::ip_list_t ls;
		ls = std::move(ipf::filter("....",ip_pool));	// lex reverse sort
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("1...",ip_pool));	// filter 1
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("46.70..",ip_pool)); // filter 46.70
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("46|46|46|46",ip_pool)); // filter 46
		for (const auto &x : ls)
			std::cout << x << std::endl;
			
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << std::endl;
	}
	return 0;
}

