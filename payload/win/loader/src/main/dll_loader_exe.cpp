#include "hermit.hpp"

INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, INT nCmdShow)
{    
    Hermit::DLLLoader();
    return EXIT_SUCCESS;
}
