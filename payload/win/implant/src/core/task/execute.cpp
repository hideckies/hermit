#include "core/task.hpp"

namespace Task
{
	std::wstring Execute(const std::wstring& wCmd)
	{
		std::wstring result;

		result = System::Process::ExecuteCmd(wCmd);
		if (wcscmp(result.c_str(), L"") == 0)
		{
			return L"Success: Command have been executed.";
		}
		return result;
	}
}
