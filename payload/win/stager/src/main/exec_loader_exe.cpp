#include "hermit.hpp"

INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, INT nCmdShow)
{    
    Hermit::LoadExecutable();
    return EXIT_SUCCESS;
}