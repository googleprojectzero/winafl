BOOL EnableAndValidateIptServices(VOID);
BOOL ConfigureBufferSize(_In_ PWCHAR pwszSize, _Inout_ PIPT_OPTIONS pOptions);
BOOL ConfigureTraceFlags(_In_ PWCHAR pwszFlags, _Inout_ PIPT_OPTIONS pOptions);
PIPT_TRACE_DATA GetIptTrace(HANDLE hProcess);
