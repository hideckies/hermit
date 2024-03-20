#include "hermit.hpp"

INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, INT nCmdShow)
{    
    Hermit::LoadDLL();
    return EXIT_SUCCESS;
}