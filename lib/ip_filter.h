#pragma once
#include <string>
#include <map>
#include <vector>
#include <functional>

namespace ipf 
{
    using ip_pool_t = std::multimap<unsigned, std::string, std::greater<unsigned> >;
    using ip_list_t = std::vector<std::string>;

    // read ip adresses from std::cin and return map {hash(ip),string(ip)}
    ip_pool_t get_ip_pool();

    // "...", pool - out all ip addresses in pool
    // "|||", pool - out all ip addresses in pool
    // "1...","1|.|", pool - out all ip addresses containing in the pos first key: 1 
    // "...1", pool - out all ip addresses containing in the pos fourth key: 1 
    // "255..1", pool - out all ip addresses containing in the pos first key: 255 and fourth key: 1 
    // ".1|255.", pool - out all ip addresses containing in the pos second key: 1 or third key: 255 
    // "1|.255.", pool - out all ip addresses containing in the pos firts key: 1 or third key: 255 
    // "1.|255.", pool - out all ip addresses containing in the pos firts key: 1 and third key: 255 
    ip_list_t filter(const std::string&,const ipf::ip_pool_t&);

}
