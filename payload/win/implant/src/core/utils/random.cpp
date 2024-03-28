#include "core/utils.hpp"

namespace Utils::Random
{
    INT RandomINT() {
	    srand((unsigned) time(NULL));
	    return rand();
    }
}