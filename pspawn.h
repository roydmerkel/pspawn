#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#if !defined(__cplusplus) && defined(__cplusplus_cli)
#define __cplusplus __cplusplus_cli
#endif

#if !defined(__cplusplus) && defined(__embedded_cplusplus)
#define __cplusplus __embedded_cplusplus
#endif

#if defined(__cplusplus)
	extern "C" {
#endif
		HANDLE __cdecl pspawnvpe(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv,
		LPCSTR const FAR *envp
		);
HANDLE __cdecl pspawnvp(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv
		);
HANDLE __cdecl pspawnve(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv,
		LPCSTR const FAR *envp
		);
HANDLE __cdecl pspawnv(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv
		);
HANDLE __cdecl pspawnlpe (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        );
HANDLE __cdecl pspawnlp (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        );
HANDLE __cdecl pspawnle (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        );
HANDLE __cdecl pspawnl (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        );

HANDLE __cdecl pwspawnvpe(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv,
		LPCWSTR const FAR *envp
		);
HANDLE __cdecl pwspawnvp(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv
		);
HANDLE __cdecl pwspawnve(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv,
		LPCWSTR const FAR *envp
		);
HANDLE __cdecl pwspawnv(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv
		);
HANDLE __cdecl pwspawnlpe (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        );
HANDLE __cdecl pwspawnlp (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        );
HANDLE __cdecl pwspawnle (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        );
HANDLE __cdecl pwspawnl (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        );

HANDLE __cdecl ptspawnvpe(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv,
		LPCTSTR const FAR *envp
		);
HANDLE __cdecl ptspawnvp(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv
		);
HANDLE __cdecl ptspawnve(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv,
		LPCTSTR const FAR *envp
		);
HANDLE __cdecl ptspawnv(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv
		);
HANDLE __cdecl ptspawnlpe (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        );
HANDLE __cdecl ptspawnlp (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        );
HANDLE __cdecl ptspawnle (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        );
HANDLE __cdecl ptspawnl (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        );
#if defined(__cplusplus)
	}
#endif
