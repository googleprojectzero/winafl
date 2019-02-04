BOOL EnableAndValidateIptServices(VOID);
BOOL ConfigureBufferSize(_In_ DWORD dwSize, _Inout_ PIPT_OPTIONS pOptions);
BOOL ConfigureTraceFlags(_In_ DWORD dwFlags, _Inout_ PIPT_OPTIONS pOptions);
PIPT_TRACE_DATA GetIptTrace(HANDLE hProcess);
