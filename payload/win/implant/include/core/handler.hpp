#ifndef HERMIT_CORE_HANDLER_HPP
#define HERMIT_CORE_HANDLER_HPP

#include "core/task.hpp"
#include "core/state.hpp"
#include "core/system.hpp"
#include "core/utils.hpp"

namespace Handler
{
	std::wstring GetInitialInfo(State::StateManager& sm);
	VOID InitHTTP(State::StateManager& sm);
	VOID CloseHTTP(State::StateManager& sm);
	BOOL CheckIn(State::StateManager& sm, const std::wstring& wInfoJson);
	BOOL GetTask(State::StateManager& sm);
	BOOL ExecuteTask(State::StateManager& sm);
	BOOL SendTaskResult(State::StateManager& sm);
}

#endif // HERMIT_CORE_HANDLER_HPP