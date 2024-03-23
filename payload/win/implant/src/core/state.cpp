#include "core/state.hpp"

namespace State
{
    VOID StateManager::SetHInstance(HINSTANCE hInstance)
    {
        currState.hInstance = hInstance;
    }

    VOID StateManager::SetCmdShow(INT nCmdShow)
    {
        currState.nCmdShow = nCmdShow;
    }

    VOID StateManager::SetPayloadType(LPCWSTR lpPayloadType)
    {
        currState.lpPayloadType = lpPayloadType;
    }

    VOID StateManager::SetListenerProtocol(LPCWSTR lpProtocol)
    {
        currState.lpListenerProtocol = lpProtocol;
    }

    VOID StateManager::SetListenerHost(LPCWSTR lpHost)
    {
        currState.lpListenerHost = lpHost;
    }

    VOID StateManager::SetListenerPort(INTERNET_PORT nPort)
    {
        currState.nListenerPort = nPort;
    }

    VOID StateManager::SetReqPathCheckIn(LPCWSTR lpReqPathCheckIn)
    {
        currState.lpReqPathCheckIn = lpReqPathCheckIn;
    }

    VOID StateManager::SetReqPathDownload(LPCWSTR lpReqPathDownload)
    {
        currState.lpReqPathDownload = lpReqPathDownload;
    }

    VOID StateManager::SetReqPathTaskGet(LPCWSTR lpReqPathTaskGet)
    {
        currState.lpReqPathTaskGet = lpReqPathTaskGet;
    }

    VOID StateManager::SetReqPathTaskResult(LPCWSTR lpReqPathTaskResult)
    {
        currState.lpReqPathTaskResult = lpReqPathTaskResult;
    }

    VOID StateManager::SetReqPathUpload(LPCWSTR lpReqPathUpload)
    {
        currState.lpReqPathUpload = lpReqPathUpload;
    }

    VOID StateManager::SetReqPathWebSocket(LPCWSTR lpReqPathWebSocket)
    {
        currState.lpReqPathWebSocket = lpReqPathWebSocket;
    }

    VOID StateManager::SetSleep(INT nSleep)
    {
        currState.nSleep = nSleep;
    }

    VOID StateManager::SetJitter(INT nJitter)
    {
        currState.nJitter = nJitter;
    }

    VOID StateManager::SetKillDate(INT nKillDate)
    {
        currState.nKillDate = nKillDate;
    }

    VOID StateManager::SetUUID(const std::wstring& wUUID)
    {
        currState.wUUID = wUUID;
    }

    VOID StateManager::SetTask(const std::wstring& wTask)
    {
        currState.wTask = wTask;
    }

    VOID StateManager::SetTaskResult(const std::wstring& wTaskResult)
    {
        currState.wTaskResult = wTaskResult;
    }

    VOID StateManager::SetHSession(HINTERNET hSession)
    {
        currState.hSession = hSession;
    }

    VOID StateManager::SetHConnect(HINTERNET hConnect)
    {
        currState.hConnect = hConnect;
    }

    VOID StateManager::SetHRequest(HINTERNET hRequest)
    {
        currState.hRequest = hRequest;
    }

    VOID StateManager::SetQuit(BOOL bQuit)
    {
        currState.bQuit = bQuit;
    }

    HINSTANCE StateManager::GetHInstance() const
    {
        return currState.hInstance;
    }

    INT StateManager::GetCmdShow() const
    {
        return currState.nCmdShow;
    }

    LPCWSTR StateManager::GetPayloadType() const
    {
        return currState.lpPayloadType;
    }

    LPCWSTR StateManager::GetListenerProtocol() const
    {
        return currState.lpListenerProtocol;
    }
 
    LPCWSTR StateManager::GetListenerHost() const
    {
        return currState.lpListenerHost;
    }

    INTERNET_PORT StateManager::GetListenerPort() const
    {
        return currState.nListenerPort;
    }

    LPCWSTR StateManager::GetReqPathCheckIn() const
    {
        return currState.lpReqPathCheckIn;
    }

    LPCWSTR StateManager::GetReqPathDownload() const
    {
        return currState.lpReqPathDownload;
    }

    LPCWSTR StateManager::GetReqPathTaskGet() const
    {
        return currState.lpReqPathTaskGet;
    }

    LPCWSTR StateManager::GetReqPathTaskResult() const
    {
        return currState.lpReqPathTaskResult;
    }

    LPCWSTR StateManager::GetReqPathUpload() const
    {
        return currState.lpReqPathUpload;
    }

    LPCWSTR StateManager::GetReqPathWebSocket() const
    {
        return currState.lpReqPathWebSocket;
    }

    INT StateManager::GetSleep() const
    {
        return currState.nSleep;
    }

    INT StateManager::GetJitter() const
    {
        return currState.nJitter;
    }

    INT StateManager::GetKillDate() const
    {
        return currState.nKillDate;
    }

    std::wstring StateManager::GetUUID() const
    {
        return currState.wUUID;
    }

    std::wstring StateManager::GetTask() const
    {
        return currState.wTask;
    }

    std::wstring StateManager::GetTaskResult() const
    {
        return currState.wTaskResult;
    }

    HINTERNET StateManager::GetHSession() const
    {
        return currState.hSession;
    }

    HINTERNET StateManager::GetHConnect() const
    {
        return currState.hConnect;
    }

    HINTERNET StateManager::GetHRequest() const
    {
        return currState.hRequest;
    }

    BOOL StateManager::GetQuit() const
    {
        return currState.bQuit;
    }
}