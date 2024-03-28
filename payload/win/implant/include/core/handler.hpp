#ifndef HERMIT_CORE_HANDLER_HPP
#define HERMIT_CORE_HANDLER_HPP

#include "core/task.hpp"
#include "core/procs.hpp"
#include "core/state.hpp"
#include "core/system.hpp"
#include "core/utils.hpp"

namespace Handler
{
	VOID HTTPInit(State::PState pState);
	VOID HTTPClose(State::PState pState);
	std::wstring GetInitialInfoJSON(State::PState pState);
	BOOL CheckIn(State::PState pState, const std::wstring& wInfoJson);
	BOOL TaskGet(State::PState pState);
	BOOL TaskExecute(State::PState pState);
	BOOL TaskResultSend(State::PState pState);
	BOOL Task(State::PState pState);
	BOOL SocketAccept(State::PState pState);
	BOOL SocketRead(State::PState pState);
	// BOOL SocketClose(State::PState pState);
	// BOOL SocketKill(State::PState pState);
	BOOL Socket(State::PState pState);
}

#endif // HERMIT_CORE_HANDLER_HPP