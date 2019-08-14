#pragma once
#include <string>
#include <map>
#include <vector>
#include <functional>

namespace ipf 
{
    using ip_pool_t = std::multimap<unsigned, std::string, std::greater<unsigned>>;
    using ip_list_t = std::vector<std::string>;

    unsigned get_key(const std::string&, char);
    void sort_revers_lex(const ip_pool_t&);
    void filter1(const ipf::ip_pool_t&);
    void filter4670(const ipf::ip_pool_t&);
    void filter46(const ipf::ip_pool_t&);

    ip_list_t filter(const std::string&,const ipf::ip_pool_t&);
}