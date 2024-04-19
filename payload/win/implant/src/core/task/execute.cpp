#include "core/task.hpp"

namespace Task
{
	std::wstring Execute(State::PSTATE pState, const std::wstring& wCmd)
	{
		std::wstring result;

		result = System::Process::ExecuteCmd(pState->pProcs, wCmd);
		if (wcscmp(result.c_str(), L"") == 0)
		{
			return L"Success: Command have been executed.";
		}
		return result;
	}
}
