#include <cassert>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <deque>
#include <algorithm>
#include <iterator>
#include <map>
#include <functional>

using str_t = std::string;

// ("",  '.') -> 0
// ("11", '.') -> 11<<8
// ("..", '.') -> 0<<8 + 0
// ("11.", '.') -> 11<<8 + 0
// (".11", '.') -> 0<<8 + 11
// ("11.22.33.255", '.') -> ((11<<8 + 22)<<8 + 33)<<8 + 255
auto get_key(const str_t &s, char zapendya)
{
    unsigned key = 0;
    auto stop = s.find_first_of(zapendya);
    decltype(stop) start = 0;
    while (stop != str_t::npos)
    {
        key = (key<<8) | std::stoi(s.substr(start, stop - start));
        start = stop + 1;
        stop = s.find_first_of(zapendya, start);
    }
    
    key = (key<<8) | std::stoi(s.substr(start));
    return key;
}

int main(int, char const **)
{
    try
    {
        std::multimap<unsigned,std::string,std::greater<unsigned>> ip_pool;

        for(std::string line; std::getline(std::cin, line);)
        {
            auto ip_str = line.substr(0, line.find_first_of('\t'));
            ip_pool.insert({ get_key(ip_str,'.'),ip_str});
        }
   
        // TODO reverse lexicographically sort
        std::for_each(ip_pool.cbegin(), ip_pool.cend(), [](decltype(*ip_pool.cbegin()) p) {std::cout << p.second << std::endl; });
        
        // TODO filter by first byte and output
        // ip = filter(1)
        auto it = ip_pool.lower_bound(0x01ffffff);
        while (it != ip_pool.end() && it->first > 0x01000000)
        {
            if ((it->first & 0xff000000) == 0x01000000)
            std::cout << it->second << std::endl;
            ++it;
        }
        
        // TODO filter by first and second bytes and output
        // ip = filter(46, 70)
        it = ip_pool.lower_bound(0x2e46ffff);
  
        while (it != ip_pool.end() && it->first > 0x2e450000)
        {
            if ((it->first & 0xffff0000) == 0x2e460000)
            std::cout << it->second << std::endl;
            ++it;
        }
        
        // TODO filter by any byte and output
        // ip = filter_any(46)
        std::for_each(ip_pool.cbegin(), ip_pool.cend(),
   
            [](decltype(*ip_pool.cbegin()) p)
            {
                if (((p.first & 0xff000000) == 0x2e000000) || ((p.first & 0x00ff0000) == 0x002e0000) ||
                    ((p.first & 0x0000ff00) == 0x00002e00) || ((p.first & 0x000000ff) == 0x0000002e))
                    std::cout << p.second << std::endl;
            }
        );
    }
    catch(const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}