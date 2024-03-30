#include "core/utils.hpp"

namespace Utils::Random
{
    INT RandomINT()
    {
	    srand((unsigned) time(NULL));
	    return rand();
    }

    VOID RandomSleep(INT nSleep, INT nJitter)
    {
        srand(time(NULL));

        INT randJitter = rand() % (2 * nJitter);
        INT randSleep = nSleep + randJitter;

        Sleep(randSleep * 1000);
    }
}