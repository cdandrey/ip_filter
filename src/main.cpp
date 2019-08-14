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

		//ipf::sort_revers_lex(ip_pool);
		//ipf::filter1(ip_pool);
		//ipf::filter4670(ip_pool);
		//ipf::filter46(ip_pool);

		ipf::ip_list_t ls;
		ls = std::move(ipf::filter("46.70|86.131",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("1...",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("46.70..",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("46|46|46|46",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("16.236.0.173",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("255|0..0",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("255|0.0|",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("255.255.1.",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;

		ls = std::move(ipf::filter("5|.154.",ip_pool));
		for (const auto &x : ls)
			std::cout << x << std::endl;
			
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << std::endl;
	}
	return 0;
}

