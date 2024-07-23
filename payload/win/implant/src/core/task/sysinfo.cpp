#include "core/task.hpp"

namespace Task
{
    std::wstring Sysinfo(State::PSTATE pState)
    {
        std::wstring wResult = L"";

        // ----------------------------------------------
        // Hardware
        // ----------------------------------------------

        SYSTEM_INFO si;
        pState->pProcs->lpGetSystemInfo(&si);

        wResult += L"Hardware:\n";
        wResult += L"  OEM ID: " + Utils::Convert::DWORDToWstring(si.dwOemId) + L"\n";
        wResult += L"  Number of Processors: " + Utils::Convert::DWORDToWstring(si.dwNumberOfProcessors) + L"\n";
        wResult += L"  Processor Type: " + Utils::Convert::DWORDToWstring(si.dwProcessorType) + L"\n";
        wResult += L"  Processor Level: " + Utils::Convert::WORDToWstring(si.wProcessorLevel) + L"\n";
        wResult += L"  Processor Revision: " + Utils::Convert::WORDToWstring(si.wProcessorRevision) + L"\n";
        wResult += L"  Page Size: " + Utils::Convert::DWORDToWstring(si.dwPageSize) + L"\n";
        // Minimum Application Address
        uintptr_t pMinAppAddr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
        std::wstringstream ssMinAppAddr;
        ssMinAppAddr << std::hex << std::setfill(L'0') << std::setw(sizeof(uintptr_t) * 2) << pMinAppAddr;
        std::wstring wMinAppAddr = L"0x" + ssMinAppAddr.str();
        wResult += L"  Minimum Application Address: " + wMinAppAddr + L"\n";
        // Maximum Application Address
        uintptr_t pMaxAppAddr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
        std::wstringstream ssMaxAppAddr;
        ssMaxAppAddr << std::hex << std::setfill(L'0') << std::setw(sizeof(uintptr_t) * 2) << pMaxAppAddr;
        std::wstring wMaxAppAddr = L"0x" + ssMaxAppAddr.str();
        wResult += L"  Maximum Application Address: " + std::wstring(wMaxAppAddr) + L"\n";
        wResult += L"  Active Processor Mask: " + Utils::Convert::DWORDToWstring(si.dwActiveProcessorMask) + L"\n";

        // ----------------------------------------------
        // OS Version
        // ----------------------------------------------

        OSVERSIONINFOEXW osvi;
        RtlZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

        pState->pProcs->lpGetVersionExW(&osvi);

        wResult += L"OS Version:\n";
        wResult += L"  OS Version Information Size: " + Utils::Convert::DWORDToWstring(osvi.dwOSVersionInfoSize) + L"\n";
        wResult += L"  Major Version: " + Utils::Convert::DWORDToWstring(osvi.dwMajorVersion) + L"\n";
        wResult += L"  Minor Version: " + Utils::Convert::DWORDToWstring(osvi.dwMinorVersion) + L"\n";
        wResult += L"  Build Number: " + Utils::Convert::DWORDToWstring(osvi.dwBuildNumber) + L"\n";
        wResult += L"  Platform ID: " + Utils::Convert::DWORDToWstring(osvi.dwPlatformId) + L"\n";
        wResult += L"  CSD Version: " + std::wstring(osvi.szCSDVersion) + L"\n";
        wResult += L"  Suite Mask: " + Utils::Convert::WORDToWstring(osvi.wSuiteMask) + L"\n";

        // ----------------------------------------------
        // System & Local Time
        // ----------------------------------------------

        SYSTEMTIME st, lt;
        pState->pProcs->lpGetSystemTime(&st);
        pState->pProcs->lpGetLocalTime(&lt);

        wResult += L"System Time: " +
                    Utils::Convert::WORDToWstring(st.wYear) + L"/" +
                    Utils::Convert::WORDToWstring(st.wMonth) + L"/" +
                    Utils::Convert::WORDToWstring(st.wDay) + L" " +
                    Utils::Convert::WORDToWstring(st.wHour) + L":" +
                    Utils::Convert::WORDToWstring(st.wMinute) + L":" +
                    Utils::Convert::WORDToWstring(st.wSecond) + L"." +
                    Utils::Convert::WORDToWstring(st.wMilliseconds) + L"\n";
        wResult += L"Local Time: " +
                    Utils::Convert::WORDToWstring(lt.wYear) + L"/" +
                    Utils::Convert::WORDToWstring(lt.wMonth) + L"/" +
                    Utils::Convert::WORDToWstring(lt.wDay) + L" " +
                    Utils::Convert::WORDToWstring(lt.wHour) + L":" +
                    Utils::Convert::WORDToWstring(lt.wMinute) + L":" +
                    Utils::Convert::WORDToWstring(lt.wSecond) + L"." +
                    Utils::Convert::WORDToWstring(lt.wMilliseconds) + L"\n";

        // ----------------------------------------------
        // Elapsed Time from System Boot
        // ----------------------------------------------

        DWORD dwElapsedTimeMS = pState->pProcs->lpGetTickCount();
        // Convert milliseconds to seconds (float)
        DWORD dwElapsedTimeS = dwElapsedTimeMS / 1000;
        wResult += L"Elasped Time from System Boot: " + Utils::Convert::DWORDToWstring(dwElapsedTimeS) + L"s\n";

        // ----------------------------------------------
        // Computer Name
        // ----------------------------------------------

        WCHAR szComputerItems[8][32] = {
            L"NetBIOS",
            L"DNS Hostname",
            L"DNS Domain",
            L"DNS Fully-Qualified",
            L"Physical NetBIOS",
            L"Physical DNS Hostname",
            L"Physical DNS Domain",
            L"Physical DNS Fully-Qualified"
        };

        WCHAR wBufComputer[INFO_BUFFER_SIZE] = {'\0'};
        DWORD dwBufSizeComputer = INFO_BUFFER_SIZE;

        int cnf = 0;

        wResult += L"Computer Name:\n";
        for (cnf = 0; cnf < 8; cnf++)
        {
            if (pState->pProcs->lpGetComputerNameExW((COMPUTER_NAME_FORMAT)cnf, wBufComputer, &dwBufSizeComputer))
            {
                wResult += L"  " + std::wstring(szComputerItems[cnf]) + L": " + std::wstring(wBufComputer) + L"\n";
            }
        }

        // ----------------------------------------------
        // User Name
        // ----------------------------------------------

        WCHAR wBufUser[INFO_BUFFER_SIZE] = {'\0'};
        DWORD dwBufSizeUser = INFO_BUFFER_SIZE;

        if (pState->pProcs->lpGetUserNameW(wBufUser, &dwBufSizeUser))
        {
            wResult += L"User Name: " + std::wstring(wBufUser) + L"\n";
        }

        return wResult;
    }
}