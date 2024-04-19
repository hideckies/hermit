#include "core/system.hpp"

namespace Handle
{
    BOOL SetHandleInformation(
        Procs::PPROCS   pProcs,
        HANDLE          hObject,
        DWORD           dwMask,
        DWORD           dwFlags
    ) {
        // IO_STATUS_BLOCK ioStatusBlock;
        // FILE_END_OF_FILE_INFORMATION handleInfo;

        // handleInfo.Flags = dwFlags;

        // NTSTATUS status = pProcs->lpNtSetInformationFile(
        //     hObject,
        //     &ioStatusBlock,
        //     &handleInfo,
        //     sizeof(FILE_END_OF_FILE_INFORMATION),
        //     FileHandleFlagInformation
        // );
        // if (status != 0)
        // {
        //     return FALSE;
        // }

        return TRUE;
    }
}