#ifndef HERMIT_UTILS_HPP
#define HERMIT_UTILS_HPP

#include <string>
#include <vector>

std::vector<std::string> Split(std::string text, char delimiter);
std::vector<std::wstring> SplitW(std::wstring text, wchar_t delimiter);

#endif // HERMIT_UTILS_HPP