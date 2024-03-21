#include "core/utils.hpp"

namespace Utils::Split
{
    std::vector<std::wstring> Split(std::wstring text, wchar_t delimiter)
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
}

