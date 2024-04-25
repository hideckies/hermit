#include "core/utils.hpp"

namespace Utils::Random
{
    INT RandomINT()
    {
	    srand((unsigned) time(NULL));
	    return rand();
    }

    std::wstring RandomString(int nLen) 
    {
        const std::string CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        std::random_device randomDevice;
        std::mt19937 generator(randomDevice());
        std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

        std::string randStr;

        for (std::size_t i = 0; i < nLen; ++i)
        {
            randStr += CHARACTERS[distribution(generator)];
        }

        return Utils::Convert::UTF8Decode(randStr);
    }

    VOID RandomSleep(INT nSleep, INT nJitter)
    {
        srand(time(NULL));

        INT randJitter = rand() % (2 * nJitter);
        INT randSleep = nSleep + randJitter;

        Sleep(randSleep * 1000);
    }
}