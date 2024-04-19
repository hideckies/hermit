#include "core/system.hpp"

namespace Pipe
{
    BOOL PipeCreate(
        Procs::PPROCS   pProcs,
        PHANDLE         phRead,
        PHANDLE         phWrite
    ) {
        // HANDLE hPipe;
        // OBJECT_ATTRIBUTES objAttr;
        // IO_STATUS_BLOCK ioStatusBlock;

        // InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);

        // NTSTATUS ntStatus = pProcs->lpNtCreateNamedPipeFile(
        //     &hPipe,
        //     GENERIC_READ | GENERIC_WRITE,
        //     &objAttr,
        //     &ioStatusBlock,
        //     FILE_SHARE_READ | FILE_SHARE_WRITE,
        //     FILE_OPEN_IF,
        //     0,
        //     1,
        //     0,
        //     FILE_NON_DIRECTORY_FILE,
        //     1,
        //     dwSize,
        //     dwSize,
        //     nullptr
        // );
        // if (ntStatus != 0)
        // {
        //     return FALSE;
        // }

        // *phRead = hPipe;
        // *phWrite = hPipe;

        return TRUE;
    }
}