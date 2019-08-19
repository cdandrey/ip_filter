#include "ip_filter.h"

#include <iostream>
#include <algorithm>
#include <tuple>
#include <limits>

using vu_t = std::vector<unsigned>;

const unsigned C_KEY_NUM = 4;
const unsigned C_KEY_BITWIDTH = 8;
const unsigned C_KEY_MAX = (1<<C_KEY_BITWIDTH) - 1;
const unsigned C_KEY_VOID = std::numeric_limits<unsigned>::max();
const unsigned C_IP_HASH_MAX = C_KEY_VOID;
const unsigned C_OP_OR = '|';
const unsigned C_OP_AND = '.';

// ("",  '.') -> 0
// ("11", '.') -> 11<<8
// ("..", '.') -> 0<<8 + 0
// ("11.", '.') -> 11<<8 + 0
// (".11", '.') -> 0<<8 + 11
// ("11.22.33.255", '.') -> ((11<<8 + 22)<<8 + 33)<<8 + 255
unsigned get_ip_hash(const std::string &s, char zapendya)
{

	unsigned keys = 0;
	auto stop = s.find_first_of(zapendya);
	decltype(stop) start = 0;

	while (stop != std::string::npos)
	{
		keys = (keys<<8) | std::stoi(s.substr(start, stop - start));
		start = stop + 1;
		stop = s.find_first_of(zapendya, start);
	}

	keys = (keys<<8) | std::stoi(s.substr(start));
	return keys;
}
//--------------------------------------------------------------------------------------


auto parser_filter_template(const std::string &filter_template)
{
	vu_t keys;
	vu_t ops;
	unsigned n{C_KEY_VOID};
	int d{-1};
	int k{0};

    for (auto ch : filter_template)
	{
		d = ch - '0';
		if (d >= 0 && d < 10)
		{
			n = n*k + d;
			k = 10;
		} 
		else 
		{
            ops.push_back(static_cast<unsigned>(ch));
			keys.push_back(n);

			n = C_KEY_VOID;
			k = 0;
		}
	} 

	keys.push_back(n);
    ops.push_back(C_OP_OR);

	return std::make_tuple(keys,ops);
}
//--------------------------------------------------------------------------------------


auto make_mask(const vu_t &keys,const vu_t &ops)
{
    vu_t mask;
    vu_t value;
    unsigned m{0};
    unsigned v{0};

    for (unsigned i = 0; i < C_KEY_NUM; ++i)
    {
        if (keys.at(i) == C_KEY_VOID)
        {
            v <<= C_KEY_BITWIDTH;
            m <<= C_KEY_BITWIDTH;

            if ((i == C_KEY_NUM - 1) && (v != 0 || value.size() == 0)) 
            {
                mask.push_back(m);
                value.push_back(v);
            }
        }
        else if (ops.at(i) == C_OP_OR)
        {
            v = ((v<<C_KEY_BITWIDTH) | keys.at(i))<<(C_KEY_BITWIDTH*(C_KEY_NUM - i - 1));
            m = ((m<<C_KEY_BITWIDTH) | C_KEY_MAX )<<(C_KEY_BITWIDTH*(C_KEY_NUM - i - 1));

            value.push_back(v);
            mask.push_back(m);

            v = 0;
            m = 0;
        }
        else
        {
            v = (v<<C_KEY_BITWIDTH) | keys.at(i);
            m = (m<<C_KEY_BITWIDTH) | C_KEY_MAX;
        }
    }

    return std::make_tuple(value,mask);
}
//----------------------------------------------------------------------------------------


auto make_bound(const vu_t & keys,const vu_t & ops)
{
    unsigned bnd_up;
    unsigned bnd_low;

    // beginer index of keys which inclunded to boundery value
    //      ops(2) == OR -> begin == 3 -> included 3       keys
    // else ops(1) == OR -> begin == 2 -> included 2,3     keys
    // else ops(0) == OR -> begin == 1 -> included 1,2,3   keys
    // else              -> begin == 0 -> included 0,1,2,3 keys
    unsigned begin = 0;
    for (int i = C_KEY_NUM - 2; i >= 0; --i)
        if (ops.at(i) == C_OP_OR)
        {
            begin = i + 1;
            break;
        }

    // start value bnd_up
    // begin == 3 -> bnd_up == 0xff_ff_ff_00
    // begin == 2 -> bnd_up == 0xff_ff_00_00
    // begin == 1 -> bnd_up == 0xff_00_00_00
    // begin == 0 -> bnd_up == 0x00_00_00_00
    bnd_up = ( begin == 0 ) ? 0 : C_IP_HASH_MAX<<(C_KEY_BITWIDTH*(C_KEY_NUM - begin));    // shift by 32 undefined behavior

    // start value bnd_low == 0
    bnd_low = 0;

    // include keys to bnd
    int shift;
    for (unsigned i = begin; i < C_KEY_NUM; ++i)
    {
        shift = C_KEY_BITWIDTH*(C_KEY_NUM - i - 1);

        if (keys.at(i) != C_KEY_VOID) {
            bnd_up  |= keys.at(i)<<shift;
            bnd_low |= keys.at(i)<<shift;
        }
        else
        {
            bnd_up  |= C_KEY_MAX<<shift;
        }
    }

    return std::make_tuple(bnd_low,bnd_up);

}
//----------------------------------------------------------------------------------------


ipf::ip_pool_t ipf::get_ip_pool()
{
    ipf::ip_pool_t pool;

    for (std::string line; std::getline(std::cin, line);)
    {
        auto ip_str = line.substr(0, line.find_first_of('\t'));
        pool.insert({ get_ip_hash(ip_str,'.'),ip_str });
    }

    return pool;
}
//--------------------------------------------------------------------------------------


ipf::ip_list_t ipf::filter(const std::string &filter_template,const ipf::ip_pool_t &pool)
{
	vu_t keys;
	vu_t ops;

	std::tie (keys,ops) = std::move(parser_filter_template(filter_template));

	vu_t mask;
	vu_t value;

	std::tie (value,mask) = std::move(make_mask(keys,ops));

	unsigned bnd_up;
	unsigned bnd_low;

	std::tie (bnd_low,bnd_up) = std::move(make_bound(keys,ops));

	ipf::ip_list_t list;
	auto it = pool.lower_bound(bnd_up);

	while (it != pool.cend() && it->first >= bnd_low) 
	{
		for (unsigned i = 0; i < mask.size(); ++i) 
			if ((it->first & mask.at(i)) == value.at(i)) 
            {
                list.push_back(it->second);
                break;
            }

		++it;
	}

	return list;
}
//--------------------------------------------------------------------------------------


