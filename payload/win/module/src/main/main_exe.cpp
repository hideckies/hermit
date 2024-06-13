#include "hermit.hpp"

INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, INT nCmdShow)
{
    Hermit::Run();
    return EXIT_SUCCESS;
}