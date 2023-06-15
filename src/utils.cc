#include "utils.hh"

#include <sstream>
#include <string>
#include <numeric>

std::vector<std::string> split(const std::string &str, char delimiter)
{
    std::vector<std::string> res;
    if ("" == str) {
        return res;
    }

    std::stringstream ss{str};
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        res.push_back(item);
    }

    return res;
}

bool starts_with(const std::string &str, const std::string &prefix)
{
    return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
}
