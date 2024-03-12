#include "utils.hpp"

std::vector<std::string> Split(std::string text, char delimiter)
{
    int first = 0;
    int last = text.find_first_of(delimiter);

    std::vector<std::string> result;

    while (first < text.size()) {
        std::string subStr(text, first, last - first);

        result.push_back(subStr);

        first = last + 1;
        last = text.find_first_of(delimiter, first);

        if (last == std::string::npos) {
            last = text.size();
        }
    }

    return result;
}

std::vector<std::wstring> SplitW(std::wstring text, wchar_t delimiter)
{
    int first = 0;
    int last = text.find_first_of(delimiter);

    std::vector<std::wstring> result;

    while (first < text.size()) {
        std::wstring subStr(text, first, last - first);

        result.push_back(subStr);

        first = last + 1;
        last = text.find_first_of(delimiter, first);

        if (last == std::wstring::npos) {
            last = text.size();
        }
    }

    return result;
}