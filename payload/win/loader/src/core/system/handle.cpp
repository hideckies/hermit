#include "core/system.hpp"

namespace System::Handle
{
    BOOL HandleClose(Procs::PPROCS pProcs, HANDLE handle)
    {
        NTSTATUS status = CallSysInvoke(
            &pProcs->sysNtClose,
            pProcs->lpNtClose,
            handle
        );
        if (status != STATUS_SUCCESS)
        {
            return FALSE;
        }
        return TRUE;
    }

    BOOL HandleWait(Procs::PPROCS pProcs, HANDLE handle, BOOL bAlertable, PLARGE_INTEGER pTimeout)
    {
        NTSTATUS status = CallSysInvoke(
            &pProcs->sysNtWaitForSingleObject,
            pProcs->lpNtWaitForSingleObject,
            handle,
            bAlertable,
            pTimeout
        );
        if (status != STATUS_SUCCESS)
        {
            return FALSE;
        }
        return TRUE;
    }
}