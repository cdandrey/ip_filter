#include "ip_filter.h"

#include <iostream>
#include <algorithm>
#include <tuple>

enum KeyOperation {or,and};

using v_t = std::vector<int>;
using vu_t = std::vector<unsigned>;
using vko_t = std::vector<KeyOperation>;

// ("",  '.') -> 0
// ("11", '.') -> 11<<8
// ("..", '.') -> 0<<8 + 0
// ("11.", '.') -> 11<<8 + 0
// (".11", '.') -> 0<<8 + 11
// ("11.22.33.255", '.') -> ((11<<8 + 22)<<8 + 33)<<8 + 255
unsigned ipf::get_key(const std::string &s, char zapendya)
{

	unsigned key = 0;
	auto stop = s.find_first_of(zapendya);
	decltype(stop) start = 0;

	while (stop != std::string::npos)
	{
		key = (key<<8) | std::stoi(s.substr(start, stop - start));
		start = stop + 1;
		stop = s.find_first_of(zapendya, start);
	}

	key = (key<<8) | std::stoi(s.substr(start));
	return key;
}


// todo reverse lexicographically sort
void ipf::sort_revers_lex(const ipf::ip_pool_t &pool) 
{
	//std::for_each(pool.cbegin(), pool.cend(), [](decltype(*pool.cbegin()) p) {std::cout << p.second << std::endl; });
	for (const auto &p : pool )
	std::cout << p.second << std::endl;
	std::cout << std::endl;
}


// todo filter by first byte and output
// ip = filter(1)
void ipf::filter1(const ipf::ip_pool_t &pool)
{
	auto it = pool.lower_bound(0x01ffffff);
	while (it != pool.cend() && it->first > 0x01000000) 
	{
		if ((it->first & 0xff000000) == 0x01000000)
			std::cout << it->second << std::endl;
		++it;
	}
}


// TODO filter by first and second bytes and output
// ip = filter(46, 70)
void ipf::filter4670(const ipf::ip_pool_t &pool)
{
	auto it = pool.lower_bound(0x2e46ffff);
	while (it != pool.cend() && it->first > 0x2e450000) 
	{
		if ((it->first & 0xffff0000) == 0x2e460000)
			std::cout << it->second << std::endl;
		++it;
	}
}


// TODO filter by any byte and output
// ip = filter_any(46)
void ipf::filter46(const ipf::ip_pool_t &pool)
{
	std::for_each(pool.cbegin(), pool.cend(),
		[](decltype(*pool.cbegin()) p)
		{
			if (((p.first & 0xff000000) == 0x2e000000) || ((p.first & 0x00ff0000) == 0x002e0000) ||
			    ((p.first & 0x0000ff00) == 0x00002e00) || ((p.first & 0x000000ff) == 0x0000002e))
			std::cout << p.second << std::endl;
		}
	);
}

std::tuple<v_t,vko_t > parser_ip_mask(const std::string &mask)
{
	v_t key;
	vko_t op;
	int k{0};
	int n{-1};
	int p{0};
	int d{-1};

	while (p < mask.length())
	{
		d = mask.at(p) - '0';
		if (d >= 0 && d < 10)
		{
			n = n*k + d;
			k = 10;
		} 
		else 
		{
			if (mask.at(p) == '.') 
				op.push_back(KeyOperation::and);
			else if (mask.at(p) == '|')
				op.push_back(KeyOperation::or);
			else
				throw std::invalid_argument("Error: invalid ip_mask: " + mask);

			if (n > 255)
				throw std::invalid_argument("Error: invalid ip_mask: " + mask);

			key.push_back(n);
			n = -1;
			k = 0;
		}

		++p;
	} 

	key.push_back(n);

	return std::make_tuple(key,op);
}
//--------------------------------------------------------------------------------------

unsigned arr_to_uint(const vu_t &a)
{
	unsigned v{0};

	for (const auto x : a)
		v = static_cast<unsigned>(v<<8) + x;

	return v;
}
//--------------------------------------------------------------------------------------


unsigned make_hash(int first,int last,const v_t &key,unsigned init_hash,const v_t &valid_hash = {255,255,255,255},unsigned un_valid_hash = 0)
{
	vu_t tmpl_hash(key.size(),init_hash);

	for (int i = first; i < last; ++i)
		tmpl_hash[i] = (key.at(i) != -1) ? static_cast<unsigned>(valid_hash.at(i)) : un_valid_hash;

	return arr_to_uint(tmpl_hash);
}
//--------------------------------------------------------------------------------------


std::tuple<unsigned,unsigned> make_bound(unsigned bnd_up,unsigned bnd_up_n,unsigned bnd_low,unsigned bnd_low_n)
{
	if (bnd_up < bnd_up_n)
		bnd_up = bnd_up_n;

	bnd_low_n = bnd_low_n == 0 ? 0 : bnd_low_n - 1;
	if (bnd_low > bnd_low_n)
		bnd_low = bnd_low_n;

	return std::make_tuple(bnd_up,bnd_low);
}
//--------------------------------------------------------------------------------------


std::tuple<vu_t,vu_t,unsigned,unsigned> make_mask(const v_t &key,const vko_t &op)
{
	vu_t msk;
	vu_t val;
	unsigned bnd_up{0};
	unsigned bnd_low{0xffffffff};
	int op_first{-1};
	v_t max(key.size(),255);

	for (int i = 0; i < op.size(); ++i)
	{
		if (op.at(i) == KeyOperation::or && op_first != -1)
		{
			msk.push_back(make_hash(op_first,i + 1,key,0,max,0));
			val.push_back(make_hash(op_first,i + 1,key,0,key,0));

			std::tie (bnd_up,bnd_low) = make_bound(bnd_up,make_hash(op_first,i + 1,key,255,key,255),bnd_low,val.at(val.size() - 1));

			op_first = -1;
		}        
		else if (op.at(i) == KeyOperation::or)
		{
			msk.push_back(make_hash(i,i + 1,key,0,max,0));
			val.push_back(make_hash(i,i + 1,key,0,key,255));

			std::tie (bnd_up,bnd_low) = make_bound(bnd_up,make_hash(i,i + 1,key,255,key,255),bnd_low,val.at(val.size() - 1));
		} 
		else if (op.at(i) == KeyOperation::and && op_first == -1)
		{
			op_first = i;
		}
	}

	if (op_first != -1)
	{
		msk.push_back(make_hash(op_first,key.size(),key,0,max,0));
		val.push_back(make_hash(op_first,key.size(),key,0,key,0));

		std::tie (bnd_up,bnd_low) = make_bound(bnd_up,make_hash(op_first,key.size(),key,255,key,255),bnd_low,val.at(val.size() - 1));
	}        
	else 
	{
		auto i{key.size() - 1};

		msk.push_back(make_hash(i,i + 1,key,0,max,0));
		val.push_back(make_hash(i,i + 1,key,0,key,255));

		std::tie (bnd_up,bnd_low) = make_bound(bnd_up,make_hash(i,i + 1,key,255,key,255),bnd_low,val.at(val.size() - 1));
	}

	return std::make_tuple(msk,val,bnd_up,bnd_low);
}
//--------------------------------------------------------------------------------------


ipf::ip_list_t ipf::filter(const std::string &mask,const ipf::ip_pool_t &pool)
{
	std::cout << std::endl << "Debug: " << mask << " - ";

	v_t key;
	vko_t op;

	std::tie (key,op) = std::move(parser_ip_mask(mask));

	// Debug out ///////////////////////////
	for (const auto &x : key)
		std::cout << x << " ";
	for (const auto &x : op)
		x == KeyOperation::or ? std::cout << "or " : std::cout << "and ";
	std::cout << std::endl;
	/////////////////////////////////////////

	vu_t msk;
	vu_t val;
	unsigned bnd_up;
	unsigned bnd_low;

	std::tie (msk,val,bnd_up,bnd_low) = std::move(make_mask(key,op));

	// Debug out ///////////////////////////
	std::cout.setf(std::ios::hex,std::ios::basefield);
	std::cout.setf(std::ios::showbase);
	std::cout << "Debag: msk { ";
	for (const auto &x : msk) 
		std::cout << x << " ";
	std::cout << "}" << std::endl;   

	std::cout << "Debag: val { ";
	for (const auto &x : val)
		std::cout << x << " ";
	std::cout << "}" << std::endl;   

	std::cout << "Debug: bnd_up: " << bnd_up << "   bnd_low: " << bnd_low << std::endl;
	std::cout.unsetf(std::ios::basefield);
	/////////////////////////////////////////

	ipf::ip_list_t list;
	auto it = pool.lower_bound(bnd_up);
	bool is_equal;
	while (it != pool.cend() && it->first > bnd_low) 
	{
		is_equal = false;
		for (int i = 0; i < msk.size(); ++i) 
			is_equal = is_equal || ((it->first & msk.at(i)) == val.at(i));

		if (is_equal)
			list.push_back(it->second);

		++it;
	}

	return list;
}