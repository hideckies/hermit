#include <iostream>
#include <ctype.h>
#include <iomanip>
#include <map>
#include <string>
#include <cstring>

#define HASH_IV     0x35
#define RANDOM_ADDR 0xab10f29f

char* toUpper(const char* str)
{
    size_t dwLen = strlen(str);
    char result[dwLen + 1];

    for (size_t i = 0; i < dwLen; i++)
    {
        result[i] = toupper(str[i]);
    }
    result[dwLen] = '\0';
    
    return strdup(result);
}

unsigned long calcHash(const char* str)
{
    unsigned long hash = HASH_IV;
	const unsigned char* s = (const unsigned char*)str;

	while (*s)
    {
        hash = hash * RANDOM_ADDR + (*s);
        *s++;
    }

	return hash & 0xFFFFFFFF;
}

int main()
{
    std::map<std::string, unsigned long> myMap;

    char modules[3][30] = {"kernel32.dll", "ntdll.dll", "user32.dll"};

    for (int i = 0; i < 3; i++)
    {
        char* moduleUpper = toUpper(modules[i]);

        // Make a key
        char buffer[100];
        std::sprintf(buffer, "#define HASH_MODULE_%s", moduleUpper);
        std::string key(buffer);
        // Remvoe '.DLL' from the key.
        key = key.substr(0, key.length() - 4);

        myMap[key] = calcHash(modules[i]);
    }

    // Get max key length for the map.
    size_t maxLen = 0;
    for (const auto& pair : myMap)
    {
        size_t keyLen = pair.first.length();
        if (keyLen > maxLen)
        {
            maxLen = keyLen;
        }
    }

    // Output
    for (const auto& pair : myMap)
    {
        printf("%-*s 0x%lx\n", static_cast<int>(maxLen), pair.first.c_str(), pair.second);
    }
}