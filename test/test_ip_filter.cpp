
#include <iostream>
#include <string>
#include <gtest/gtest.h>
#include "../../ip_filter/lib/ip_filter.h"

const int C_MAX_LEN_IP{15};
const int C_MAX_IP{255};
ipf::ip_pool_t ip_pool;

unsigned get_ip_hash(const std::string &str)
{
    int n{0};
    unsigned key{0};

	for (const auto & c : str)
	{
		if (c != '.')
		{
			n = n*10 + (c - '0');
		}
		else
		{
			key = static_cast<unsigned>(key<<8) + n;
			n = 0;
		}
	}
	
	return static_cast<unsigned>(key<<8) + n;
}
//-----------------------------------------------------------------------------


TEST (test_ip_filter, test_input_data)
{
    int i{0};
    int n{0};
    unsigned key{0};

    for (std::string line; std::getline(std::cin, line);)
    {
        i = 0;
		n = 0;
		key = 0;

        while ((line.at(i) == '.') || (line.at(i) - '0' >= 0 && line.at(i) - '0' <= 9))
        {
            EXPECT_LT(i,C_MAX_LEN_IP);

			if (line.at(i) != '.')
			{
					n = n*10 + (line.at(i) - '0');
			}
			else
			{
				EXPECT_GE(n,0);
				EXPECT_LE(n,C_MAX_IP);
				key = static_cast<unsigned>(key<<8) + n;
				n = 0;
			}

            ++i;
        }
        
        EXPECT_GE(n,0);
        EXPECT_LE(n,C_MAX_IP);
        key = static_cast<unsigned>(key<<8) + n;

        ip_pool.insert(make_pair(key,line.substr(0, i)));
    }
}
//-----------------------------------------------------------------------------


TEST(test_ip_filter,test_revers_lex_sort)
{
    // ...
    ipf::ip_list_t ip_sort_list = ipf::filter("...",ip_pool);	

    EXPECT_EQ(ip_sort_list.size(),ip_pool.size());

    for (unsigned i = 0; i < ip_sort_list.size() - 1; ++i)
    {

        EXPECT_GE(get_ip_hash(ip_sort_list.at(i)),get_ip_hash(ip_sort_list.at(i + 1))) << ip_sort_list.at(i) << " vs " << ip_sort_list.at(i + 1);
    }

    // |||
    ip_sort_list = ipf::filter("|||",ip_pool);	

    EXPECT_EQ(ip_sort_list.size(),ip_pool.size());

    for (unsigned i = 0; i < ip_sort_list.size() - 1; ++i)
    {

        EXPECT_GE(get_ip_hash(ip_sort_list.at(i)),get_ip_hash(ip_sort_list.at(i + 1))) << ip_sort_list.at(i) << " vs " << ip_sort_list.at(i + 1);
    }
}
//-----------------------------------------------------------------------------


TEST(test_ip_filter,test_filter_1)
{
    // 1...
    ipf::ip_list_t ip_list = ipf::filter("1...",ip_pool);	

	unsigned cnt{0};
    for (const auto & p : ip_pool)
		if (p.second.substr(0,2) == static_cast<std::string>("1."))
			++cnt;

    EXPECT_EQ(ip_list.size(),cnt);

	for (const auto & str : ip_list)
	{
		EXPECT_EQ(str.substr(0,2),"1.") << str;
	}

    // 1|.|
    ip_list = ipf::filter("1|.|",ip_pool);	

	cnt = 0;
    for (const auto & p : ip_pool)
		if (p.second.substr(0,2) == static_cast<std::string>("1."))
			++cnt;

    EXPECT_EQ(ip_list.size(),cnt);

	for (const auto & str : ip_list)
	{
		EXPECT_EQ(str.substr(0,2),"1.") << str;
	}

}
//-----------------------------------------------------------------------------


TEST(test_ip_filter,test_filter_46_70)
{
    ipf::ip_list_t ip_list = ipf::filter("46.70..",ip_pool);	

	unsigned cnt{0};
    for (const auto & p : ip_pool)
		if (p.second.substr(0,6) == static_cast<std::string>("46.70."))
			++cnt;

    EXPECT_EQ(ip_list.size(),cnt);

	for (const auto & str : ip_list)
	{
		EXPECT_EQ(str.substr(0,6),"46.70.") << str;
	}

}
//-----------------------------------------------------------------------------


TEST(test_ip_filter,test_filter_5_31)
{
    // 5|.31.
    ipf::ip_list_t ip_list = ipf::filter("5|.31.",ip_pool);	

	unsigned cnt{0};
    for (const auto & p : ip_pool) {
		if ((p.second.substr(0,2) == static_cast<std::string>("5.")) ||
		    (p.second.substr(p.second.find_last_of('.') - 3,4) == static_cast<std::string>(".31.")))
			++cnt;
    }

    EXPECT_EQ(ip_list.size(),cnt);

	for (const auto & str : ip_list)
	{
		EXPECT_TRUE((str.substr(0,2) == static_cast<std::string>("5.")) ||
		            (str.substr(str.find_last_of('.') - 3,4) == static_cast<std::string>(".31.")));
	}

    // 5.|31|
    ip_list = ipf::filter("5.|31|",ip_pool);	

	cnt = 0;
    for (const auto & p : ip_pool) {
		if ((p.second.substr(0,2) == static_cast<std::string>("5.")) &&
		    (p.second.substr(p.second.find_last_of('.') - 3,4) == static_cast<std::string>(".31.")))
			++cnt;
    }

    EXPECT_EQ(ip_list.size(),cnt);

	for (const auto & str : ip_list)
	{
		EXPECT_TRUE((str.substr(0,2) == static_cast<std::string>("5.")) &&
		            (str.substr(str.find_last_of('.') - 3,4) == static_cast<std::string>(".31.")));
	}
}
//-----------------------------------------------------------------------------


TEST(test_ip_filter,test_filter_89___136)
{
    ipf::ip_list_t ip_list = ipf::filter("89.|.136",ip_pool);	

	unsigned cnt{0};
    for (const auto & p : ip_pool) {
		if ((p.second.substr(0,3) == static_cast<std::string>("89.")) &&
		    (p.second.substr(p.second.find_last_of('.'),4) == static_cast<std::string>(".136")))
			++cnt;
    }

    EXPECT_EQ(ip_list.size(),cnt);

	for (const auto & str : ip_list)
	{
		EXPECT_TRUE((str.substr(0,3) == static_cast<std::string>("89.")) &&
					(str.substr(str.find_last_of('.'),4) == static_cast<std::string>(".136")));
	}

    ip_list = ipf::filter("89|..136",ip_pool);	

	cnt = 0;
    for (const auto & p : ip_pool) {
		if ((p.second.substr(0,3) == static_cast<std::string>("89.")) ||
		    (p.second.substr(p.second.find_last_of('.'),4) == static_cast<std::string>(".136")))
			++cnt;
    }

    EXPECT_EQ(ip_list.size(),cnt);

	for (const auto & str : ip_list)
	{
		EXPECT_TRUE((str.substr(0,3) == static_cast<std::string>("89.")) ||
					(str.substr(str.find_last_of('.'),4) == static_cast<std::string>(".136")));
	}
}
//-----------------------------------------------------------------------------


TEST(test_ip_filter,test_filter_46)
{
    ipf::ip_list_t ip_list = ipf::filter("46|46|46|46",ip_pool);	

	unsigned cnt{0};
    for (const auto & p : ip_pool)
		if ((p.second.substr(0,3) == static_cast<std::string>("46.")) ||
		    (p.second.substr(p.second.find_first_of('.'),4) == static_cast<std::string>(".46.")) ||
		    (p.second.substr(p.second.find_last_of('.') - 3,4) == static_cast<std::string>(".46.")) ||
		    (p.second.substr(p.second.find_last_of('.'),3) == static_cast<std::string>(".46")))
			++cnt;

    EXPECT_EQ(ip_list.size(),cnt);

	for (const auto & str : ip_list)
	{
		EXPECT_TRUE((str.substr(0,3) == static_cast<std::string>("46.")) ||
					(str.substr(str.find_first_of('.'),4) == static_cast<std::string>(".46.")) ||
					(str.substr(str.find_last_of('.') - 3,4) == static_cast<std::string>(".46.")) ||
					(str.substr(str.find_last_of('.'),3) == static_cast<std::string>(".46")));
	}

}
//-----------------------------------------------------------------------------


int main (int argc,char *argv[])
{
    ::testing::InitGoogleTest(&argc,argv);

    return RUN_ALL_TESTS();
}
