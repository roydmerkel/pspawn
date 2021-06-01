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
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv,
		LPCSTR const FAR *envp
		);
HANDLE __cdecl pspawnvp(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv
		);
HANDLE __cdecl pspawnve(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv,
		LPCSTR const FAR *envp
		);
HANDLE __cdecl pspawnv(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv
		);
HANDLE __cdecl pspawnlpe (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        );
HANDLE __cdecl pspawnlp (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        );
HANDLE __cdecl pspawnle (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        );
HANDLE __cdecl pspawnl (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        );

HANDLE __cdecl pwspawnvpe(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv,
		LPCWSTR const FAR *envp
		);
HANDLE __cdecl pwspawnvp(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv
		);
HANDLE __cdecl pwspawnve(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv,
		LPCWSTR const FAR *envp
		);
HANDLE __cdecl pwspawnv(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv
		);
HANDLE __cdecl pwspawnlpe (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        );
HANDLE __cdecl pwspawnlp (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        );
HANDLE __cdecl pwspawnle (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        );
HANDLE __cdecl pwspawnl (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        );

HANDLE __cdecl ptspawnvpe(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv,
		LPCTSTR const FAR *envp
		);
HANDLE __cdecl ptspawnvp(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv
		);
HANDLE __cdecl ptspawnve(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv,
		LPCTSTR const FAR *envp
		);
HANDLE __cdecl ptspawnv(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv
		);
HANDLE __cdecl ptspawnlpe (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        );
HANDLE __cdecl ptspawnlp (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        );
HANDLE __cdecl ptspawnle (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        );
HANDLE __cdecl ptspawnl (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        );
#if defined(__cplusplus)
	}
#endif