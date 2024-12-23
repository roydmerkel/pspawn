#include "pspawn.h"
#include "strFuncs.h"
#include "errFuncs.h"
#include "ioinfo.h"
#include <stdarg.h>
#include <errno.h>

#ifndef va_copy
#define va_copy(dest, src) ((dest) = (src))
#endif

#ifndef USHRT_MAX
#define USHRT_MAX 0x7FFF
#endif

#ifndef _O_WTEXT
#define _O_WTEXT        0x10000 /* file mode is UTF16 (translated) */
#endif

#if _MSC_VER && _MSC_VER < 1000
typedef size_t SIZE_T;
#endif

#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES (DWORD)(-1)
#endif

typedef BOOL (*PSetHandleInformation)(HANDLE hObject, DWORD  dwMask, DWORD  dwFlags);
typedef BOOL (FAR * LPSetHandleInformation)(HANDLE hObject, DWORD  dwMask, DWORD  dwFlags);

static BOOL hasExt(LPCWSTR arg)
{
	return (lstrrchrW(arg, L'.') != NULL);
}

static BOOL isAbsolutePath(LPCWSTR arg)
{
	return (lstrpbrkW(arg, L"\\/") != NULL);
}

static BOOL nextPath(LPCWSTR * pEnvPath, LPWSTR outPath, DWORD bufSize)
{
	BOOL isQuote = FALSE;
	BOOL res = FALSE;
	const WCHAR FAR * envPathPtr = NULL;
	WCHAR FAR * outPathPtr = NULL;
	WCHAR FAR * outPathEnd = NULL;

	errno = 0;

	if(pEnvPath == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

	if(outPath == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

	if(**pEnvPath == L'\0')
	{
		errno = EINVAL;
		return FALSE;
	}

	outPathPtr = outPath;
	outPathEnd = outPath + (bufSize / sizeof outPath[0]) - 1;

	for(envPathPtr=*pEnvPath; *envPathPtr != L'\0' && outPathPtr < outPathEnd; envPathPtr++)
	{
		if(*envPathPtr == L'"')
		{
			isQuote = !isQuote;
		}
		else if(!isQuote && *envPathPtr == L';')
		{
			break;
		}
		else
		{
			*outPathPtr = *envPathPtr;
			outPathPtr++;
		}
	}
	if(*envPathPtr == L'\0')
	{
		if(*(envPathPtr - 1) != L'\\' && *(envPathPtr - 1) != L'/')
		{
			if(outPathPtr < outPathEnd)
			{
				*outPathPtr = L'\\';
				outPathPtr++;
				res = TRUE;
				*pEnvPath = envPathPtr;
			}
		}
		else
		{
			res = TRUE;
			*pEnvPath = envPathPtr;
		}
	}
	else if(!isQuote && *envPathPtr == L';')
	{
		if(*(envPathPtr - 1) != L'\\' && *(envPathPtr - 1) != L'/')
		{
			if(outPathPtr < outPathEnd)
			{
				*outPathPtr = L'\\';
				outPathPtr++;
				res = TRUE;
				envPathPtr++;
				*pEnvPath = envPathPtr;
			}
		}
		else
		{
			res = TRUE;
			envPathPtr++;
			*pEnvPath = envPathPtr;
		}
	}
	*outPathPtr = L'\0';
	if(isQuote && errno == 0)
	{
		errno = EINVAL;
	}
	else if(res == FALSE && errno == 0)
	{
		errno = ENOMEM;
	}

	return res;
}

static BOOL findExt(LPCWSTR arg,  LPWSTR outPath, DWORD bufSize)
{
	BOOL res = FALSE;
	const WCHAR FAR * argPtr = NULL;
	WCHAR * pathExtPtr = NULL;
	WCHAR * pathExt = NULL;
#if _MSC_VER >= 1400
	size_t pathExtSize;
	BOOL pathExtAllocated = FALSE;
#endif
	WCHAR FAR * outPathNullPtr = NULL;
	WCHAR FAR * outPathPtr = NULL;
	WCHAR FAR * outPathEndPtr = outPath + (bufSize / sizeof outPath[0]) - 1;

	errno = 0;

	if(arg == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

	if(outPath == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

	if(hasExt(arg))
	{
		if(GetFileAttributesW(arg) != INVALID_FILE_ATTRIBUTES)
		{
			// found.
			for(outPathPtr = outPath, argPtr = arg; *argPtr && outPathPtr < outPathEndPtr; outPathPtr++, argPtr++)
			{
				*outPathPtr = *argPtr;
			}

			*outPathPtr = L'\0';
			if(*argPtr == L'\0')
			{
				res = TRUE;
			}
			else
			{
				errno = ENOMEM;
			}
		}
		dosmaperr(GetLastError());
	}
	else
	{
#if _MSC_VER >= 1400
		if(_wdupenv_s(&pathExt, &pathExtSize, L"PATHEXT") == ENOMEM)
		{
			errno = ENOMEM;
			return FALSE;
		}
#else
		pathExt = _wgetenv(L"PATHEXT");
#endif
		if(pathExt == NULL)
		{
			pathExt = L".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH";
		}
#if _MSC_VER >= 1400
		else
		{
			pathExtAllocated = TRUE;
		}
#endif

		// found.
		for(outPathPtr = outPath, argPtr = arg; *argPtr && outPathPtr < outPathEndPtr; outPathPtr++, argPtr++)
		{
			*outPathPtr = *argPtr;
		}

		*outPathPtr = L'\0';
		if(*argPtr == L'\0')
		{
			outPathNullPtr = outPathPtr;

			for(pathExtPtr = pathExt; pathExtPtr && *pathExtPtr; pathExtPtr++)
			{
				if(*pathExtPtr == L';')
				{
					DWORD lastError = 0;
					*outPathPtr = L'\0';
					if(GetFileAttributesW(outPath) != INVALID_FILE_ATTRIBUTES)
					{
						res = TRUE;
						break;
					}
					dosmaperr(GetLastError());

					outPathPtr = outPathNullPtr;
					*outPathPtr = L'\0';
				}
				else
				{
					if(outPathPtr >= outPathEndPtr)
					{
						errno = ENOMEM;
						break;
					}
					*outPathPtr = *pathExtPtr;
					outPathPtr++;
				}
			}
			if(res == FALSE)
			{
				*outPathPtr = L'\0';
				if(GetFileAttributesW(outPath) != INVALID_FILE_ATTRIBUTES)
				{
					res = TRUE;
				}
				else
				{
					dosmaperr(GetLastError());
					if(errno == 0 || errno == ENOENT)
					{
						errno = ENOENT;
					}
					*outPathNullPtr = L'\0';
				}
			}
		}
		else
		{
			errno = ENOMEM;
		}
#if _MSC_VER >= 1400
		if(pathExtAllocated)
		{
			free(pathExt);
			pathExt = NULL;
		}
#endif
	}

	return res;
}

static BOOL valistToArray(LPCWSTR arg0, va_list *list, LPCWSTR FAR * buf, DWORD bufSize)
{
	BOOL res = FALSE;
	DWORD size = 0;
	va_list cplist;
	LPCWSTR arg;
	size_t cur = 0;
	LPCWSTR FAR * arr = buf;
	
	errno = 0;

	if(list == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

	if(arg0 == NULL)
	{
		if(size + sizeof (LPWSTR *) <= bufSize)
		{
			arr[cur++] = NULL;
			size += sizeof (LPWSTR *);

			res = TRUE;
		}
		else
		{
			errno = ENOMEM;
		}
	}
	else
	{
		va_copy(cplist, *list);

		if(size + 2 * sizeof (LPWSTR *) <= bufSize)
		{
			res = TRUE;
			arr[cur++] = arg0;
			arr[cur] = NULL;

			size += 2 * sizeof (LPWSTR *);

			arg = va_arg(cplist, LPCWSTR);
			while(arg)
			{
				if(size + sizeof (LPWSTR) > bufSize)
				{
					errno = ENOMEM;
					res = FALSE;
					break;
				}

				arr[cur++] = arg;
				arr[cur] = NULL;

				size += sizeof (LPWSTR *);

				arg = va_arg(cplist, LPCWSTR);
			}
		}
		else
		{
			errno = ENOMEM;
		}

		if(res)
		{
			va_end(*list);
			va_copy(*list, cplist);
		}
		else
		{
			va_end(cplist);
		}
	}

	return res;
}

static BOOL createEnv(LPCWSTR const FAR * envp, WCHAR FAR * buf, SIZE_T buf_size)
{
	WCHAR FAR * pBuf = NULL;
	WCHAR FAR * pBufEnd = NULL;
	CONST WCHAR FAR * ppenv = NULL;
	WCHAR FAR * pres = NULL;
	LPCWSTR CONST * env = NULL;
	LPCWSTR CONST * penv = NULL;
	LPCWSTR CONST * penvp = NULL;
	BOOL found;
	WCHAR sysRoot[] = L"SystemRoot=";

	if(buf == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

	if(buf_size < 2)
	{
		errno = ENOMEM;
		return FALSE;
	}

	pBuf = buf;
	pBufEnd = pBuf + (buf_size / sizeof pBuf[0]);

	if(envp)
	{
		env = GetEnvironmentStringsArrayW();

		if(env)
		{
			// check for CWD vars: (=<dir>:= strings.) and SystemRoot.
			// Add to env string if they don't exist.
			for(penv = env; *penv; penv++)
			{
				if(**penv == L'=' &&
					iswalpha(*((*penv) + 1)) &&
					*((*penv) + 2) == L':' &&
					*((*penv) + 3) == L'=')
				{
					found = FALSE;

					for(penvp = envp; *penvp; penvp++)
					{
						if(**penvp == L'=' && 
							*((*penvp) + 1) == *((*penv) + 1) &&
							*((*penvp) + 2) == L':' &&
							*((*penvp) + 3) == L'=')
						{
							found = TRUE;
							break;
						}
					}

					if(!found)
					{
						for(ppenv = *penv; *ppenv; ppenv++)
						{
							if(pBuf >= pBufEnd - 1)
							{
								LocalFree((HLOCAL)env);
								errno = ENOMEM;
								return FALSE;
							}
							else
							{
								*pBuf = *ppenv;
								pBuf++;
							}
						}
						if(pBuf >= pBufEnd - 1)
						{
							LocalFree((HLOCAL)env);
							errno = ENOMEM;
							return FALSE;
						}
						*pBuf = L'\0';
						pBuf++;
					}
				}
				else if(lstrncmpiW(*penv, sysRoot, sizeof sysRoot / sizeof sysRoot[0] - 1) == 0)
				{
					found = FALSE;

					for(penvp = envp; *penvp; penvp++)
					{
						if(lstrncmpiW(*penvp, sysRoot, sizeof sysRoot / sizeof sysRoot[0] - 1) == 0)
						{
							found = TRUE;
							break;
						}
					}

					if(!found)
					{
						for(ppenv = *penv; *ppenv; ppenv++)
						{
							if(pBuf >= pBufEnd - 1)
							{
								LocalFree((HLOCAL)env);
								errno = ENOMEM;
								return FALSE;
							}
							else
							{
								*pBuf = *ppenv;
								pBuf++;
							}
						}
						if(pBuf >= pBufEnd - 1)
						{
							LocalFree((HLOCAL)env);
							errno = ENOMEM;
							return FALSE;
						}
						*pBuf = L'\0';
						pBuf++;
					}
				}
			}

			// Add envp strings to len.
			for(penvp = envp; *penvp; penvp++)
			{
				for(ppenv = *penvp; *ppenv; ppenv++)
				{
					if(pBuf >= pBufEnd - 1)
					{
						LocalFree((HLOCAL)env);
						errno = ENOMEM;
						return FALSE;
					}
					else
					{
						*pBuf = *ppenv;
						pBuf++;
					}
				}
				if(pBuf >= pBufEnd - 1)
				{
					LocalFree((HLOCAL)env);
					errno = ENOMEM;
					return FALSE;
				}
				*pBuf = L'\0';
				pBuf++;
			}

			if(pBuf == buf)
			{
				*pBuf = L'\0';
				pBuf++;
			}

			*pBuf = L'\0';
			pBuf++;

			LocalFree((HLOCAL)env);
		}
	}

	return TRUE;
}

static BOOL createArg(LPCWSTR const FAR * argv, WCHAR FAR * buf, SIZE_T buf_size)
{
	BOOL containsSpace;
	BOOL hasStartQuote;
	BOOL hasEndQuote;
	WCHAR FAR * bufp = NULL;
	WCHAR FAR * endBuf = NULL;
	LPCWSTR FAR * argvp;
	CONST WCHAR FAR * pargvp;

	if(argv == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}
	else if(buf == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}
	else if(buf_size < 1)
	{
		errno = ENOMEM;
		return FALSE;
	}

	bufp = buf;
	endBuf = buf + (buf_size / sizeof buf[0]);

	for(argvp = (LPCWSTR FAR *)argv; *argvp; argvp++)
	{
		if(argvp != argv)
		{
			if(bufp >= endBuf - 1)
			{
				errno = ENOMEM;
				return FALSE;
			}
			*bufp = L' ';
			bufp++;
		}

		containsSpace = FALSE;
		hasStartQuote = FALSE;
		hasEndQuote = FALSE;
		for(pargvp = *argvp; *pargvp; pargvp++)
		{
			if(pargvp == *argvp && *pargvp == L'"')
			{
				hasStartQuote = TRUE;
			}
			else if(*(pargvp + 1) == L'\0' && *pargvp == L'"')
			{
				hasEndQuote = TRUE;
			}
			else if(*pargvp == L' ')
			{
				containsSpace = TRUE;
			}
		}
		if(containsSpace && (!hasStartQuote || !hasEndQuote))
		{
			if(bufp >= endBuf - 1)
			{
				errno = ENOMEM;
				return FALSE;
			}
			*bufp = L'"';
			bufp++;
		}
		for(pargvp = *argvp; *pargvp; pargvp++)
		{
			if(bufp >= endBuf - 1)
			{
				errno = ENOMEM;
				return FALSE;
			}
			*bufp = *pargvp;
			bufp++;
		}
		if(containsSpace && (!hasStartQuote || !hasEndQuote))
		{
			if(bufp >= endBuf - 1)
			{
				errno = ENOMEM;
				return FALSE;
			}
			*bufp = L'"';
			bufp++;
		}
	}
	*bufp = L'\0';
	bufp++;

	return TRUE;
}

static BOOL getLpReserved2(LPBYTE FAR *lpReserved2, WORD FAR *cbReserved2, WORD FAR *nh, CHAR FAR * FAR * osfile, intptr_t UNALIGNED FAR * FAR *osfhnd)
{
	int lastHandle;
	int curHandle;
	CHAR FAR * posfile;
	intptr_t UNALIGNED FAR * posfhnd;

	if(lpReserved2 == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}
	else if(cbReserved2 == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}
	else if(nh == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}
	else if(osfile == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}
	else if(osfhnd == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

#if defined(__LCC__) && defined(WIN32)
	lastHandle = FOPEN_MAX;
#elif defined (__MINGW32__) && defined (__MSVCRT__)
	lastHandle = 0;
	for(lastHandle = IOINFO_ARRAYS; lastHandle > 0 && __pioinfo[lastHandle - 1] == NULL; lastHandle--)
	{
	}
	if(lastHandle > 0)
	{
		lastHandle = ((lastHandle - 1) << IOINFO_L2E) + IOINFO_ARRAY_ELTS - 1;
	}
#elif _MSC_VER
	#if _MSC_VER >= 1000
		#if _MSC_VER >= 1900
		if (__pioinfo == NULL)
		{
			__pioinfo = setPioInfo();
		}
		#endif
		lastHandle = 0;
		for(lastHandle = IOINFO_ARRAYS; lastHandle > 0 && __pioinfo[lastHandle - 1] == NULL; lastHandle--)
		{
		}
		if(lastHandle > 0)
		{
			lastHandle = ((lastHandle - 1) << IOINFO_L2E) + IOINFO_ARRAY_ELTS - 1;
		}
	#else
		lastHandle = _nhandle - 1;
	#endif
#else
	#error unsupported.
#endif
	
	for(; lastHandle >= 0; lastHandle--)
	{
		if(_osfile(lastHandle))
		{
			break;
		}
	}
	lastHandle++;

	if(lastHandle <= 0)
	{
		*lpReserved2 = NULL;
		*cbReserved2 = 0;

		return TRUE;
	}
	else if(lastHandle > USHRT_MAX)
	{
		errno = ENOMEM;
		return FALSE;
	}

	*lpReserved2 = LocalAlloc(LPTR, sizeof (int) + lastHandle * (sizeof (char) + sizeof (intptr_t)));

	if(!*lpReserved2)
	{
		errno = ENOMEM;
		return FALSE;
	}

	*cbReserved2 = lastHandle;
	*nh = lastHandle;

	*(int UNALIGNED FAR *)(&(*lpReserved2)[0]) = *nh;
	posfile = (CHAR FAR *)(*lpReserved2 + sizeof (int));
	posfhnd = (intptr_t UNALIGNED FAR *)((LPBYTE)(posfile) + lastHandle);

	*osfile = posfile;
	*osfhnd = posfhnd;

	for(curHandle = 0; curHandle < lastHandle; curHandle++)
	{
#if defined(_MSC_VER) && _MSC_VER < 1000
		if((_osfile(curHandle) & FOPEN) != 0 && (_osfile(curHandle) & FNOINHERIT) == 0 &&
			_osfhnd(curHandle) && _osfhnd(curHandle) != (intptr_t)INVALID_HANDLE_VALUE)
		{
			*posfile = _osfile(curHandle);
			*posfhnd = _osfhnd(curHandle);
		}
#else
		ioinfo *info = _pioinfo(curHandle);

		if(info && (info->osfile & FOPEN) != 0 && (info->osfile & FNOINHERIT) == 0 &&
			info->osfhnd && info->osfhnd != (intptr_t)INVALID_HANDLE_VALUE)
		{
			*posfile = info->osfile;
			*posfhnd = info->osfhnd;
		}
#endif
		else
		{
			*posfile = 0;
			*posfhnd = (intptr_t)INVALID_HANDLE_VALUE;
		}
		posfile++;
		posfhnd++;
	}

	return TRUE;
}

HANDLE __cdecl pwspawnvpe(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv,
		LPCWSTR const FAR *envp
		)
{
	HANDLE res = INVALID_HANDLE_VALUE;

	res = pwspawnve(ppipestdin, ppipestdout, ppipestderr, filename, argv, envp);

	if((res == NULL || res == INVALID_HANDLE_VALUE) && errno == ENOENT && !isAbsolutePath(filename))
	{
		WCHAR * path;
		WCHAR * pathPtr;
		WCHAR buf[MAX_PATH+1];
#if _MSC_VER >= 1400
		size_t pathSize;
#endif

#if _MSC_VER >= 1400
		if(_wdupenv_s(&path, &pathSize, L"PATH") == ENOMEM)
		{
			errno = ENOMEM;
			return FALSE;
		}
		pathPtr = path;
#else
		path = _wgetenv(L"PATH");
		pathPtr = path;
#endif

		while(nextPath((LPCWSTR *)(&pathPtr), buf, MAX_PATH + 1))
		{
			if(lstrlenW(buf) + lstrlenW(filename) <= MAX_PATH)
			{
				lstrcatW(buf, filename);
				res = pwspawnve(ppipestdin, ppipestdout, ppipestderr, buf, argv, envp);

				if((res != NULL && res != INVALID_HANDLE_VALUE) || errno != ENOENT)
				{
					break;
				}
			}
			else
			{
				errno = ENOMEM;
				break;
			}
		}
#if _MSC_VER >= 1400
		if(path)
		{
			free(path);
			path = NULL;
		}
#endif
	}

	return res;
}

HANDLE __cdecl pwspawnvp(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv
		)
{
	return pwspawnvpe(ppipestdin, ppipestdout, ppipestderr, filename, argv, NULL);
}

HANDLE __cdecl pwspawnve(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv,
		LPCWSTR const FAR *envp
		)
{
	WCHAR outBuf[MAX_PATH + 1];
	WCHAR env[0x7FFF];
	WCHAR arg[0x7FFF];
	LPBYTE lpReserved2;
	WORD cbReserved2;
	WORD nh;
	CHAR FAR * osfile;
	intptr_t FAR * osfhnd;
	DWORD dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInformation;
	SECURITY_ATTRIBUTES saAttr;
	HANDLE g_hChildStd_IN_Rd = NULL;
	HANDLE g_hChildStd_IN_Wr = NULL;
	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;
	HANDLE g_hChildStd_ERR_Rd = NULL;
	HANDLE g_hChildStd_ERR_Wr = NULL;
	HMODULE hKernel32 = GetModuleHandle(_T("KERNEL32"));
	FARPROC pSetHandleInformation = NULL;
	if(hKernel32)
	{
		pSetHandleInformation = GetProcAddress(hKernel32, "SetHandleInformation");
	}

	if(!findExt(filename, outBuf, sizeof outBuf))
	{
		return INVALID_HANDLE_VALUE;
	}

	if(!createEnv(envp, env, sizeof env))
	{
		return INVALID_HANDLE_VALUE;
	}

	if(!createArg(argv, arg, sizeof arg))
	{
		return INVALID_HANDLE_VALUE;
	}

	if(!getLpReserved2(&lpReserved2, &cbReserved2, &nh, &osfile, &osfhnd))
	{
		return INVALID_HANDLE_VALUE;
	}

	memset(&startupInfo, '\0', sizeof (STARTUPINFOW));
	startupInfo.cb = sizeof (STARTUPINFOW);
	startupInfo.cbReserved2 = cbReserved2;
	startupInfo.lpReserved2 = lpReserved2;
	startupInfo.hStdError = (nh > _fileno(stderr)) ? (HANDLE)osfhnd[_fileno(stderr)] : INVALID_HANDLE_VALUE;
	startupInfo.hStdOutput = (nh > _fileno(stdout)) ? (HANDLE)osfhnd[_fileno(stdout)] : INVALID_HANDLE_VALUE;
	startupInfo.hStdInput = (nh > _fileno(stdin)) ? (HANDLE)osfhnd[_fileno(stdin)] : INVALID_HANDLE_VALUE;

	if(ppipestdin != NULL || ppipestdout != NULL || ppipestderr != NULL)
	{
		saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
		saAttr.bInheritHandle = TRUE;
		saAttr.lpSecurityDescriptor = NULL; 
	}

	if(ppipestdin)
	{
		if (! CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 32767)) 
		{
			LocalFree(lpReserved2);
			lpReserved2 = NULL;
			return INVALID_HANDLE_VALUE;
		}

		if (pSetHandleInformation && ! (*pSetHandleInformation)(g_hChildStd_IN_Rd, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) && GetLastError() != ERROR_CALL_NOT_IMPLEMENTED )
		{
			LocalFree(lpReserved2);
			lpReserved2 = NULL;
			CloseHandle(g_hChildStd_IN_Rd);
			CloseHandle(g_hChildStd_IN_Wr);
			return INVALID_HANDLE_VALUE;
		}

		startupInfo.hStdInput = g_hChildStd_IN_Rd;
		startupInfo.dwFlags |= STARTF_USESTDHANDLES;

		if (nh > _fileno(stdin))
		{
			osfhnd[_fileno(stdin)] = (intptr_t)g_hChildStd_IN_Rd;
		}
	}

	if(ppipestdout)
	{
		if ( ! CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 32767) ) 
		{
			LocalFree(lpReserved2);
			lpReserved2 = NULL;
			if(ppipestdin)
			{
				CloseHandle(g_hChildStd_IN_Rd);
				CloseHandle(g_hChildStd_IN_Wr);
			}
			return INVALID_HANDLE_VALUE;
		}

		if (pSetHandleInformation && ! (pSetHandleInformation)(g_hChildStd_OUT_Wr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) && GetLastError() != ERROR_CALL_NOT_IMPLEMENTED )
		{
			LocalFree(lpReserved2);
			lpReserved2 = NULL;
			if(ppipestdin)
			{
				CloseHandle(g_hChildStd_IN_Rd);
				CloseHandle(g_hChildStd_IN_Wr);
			}
			CloseHandle(g_hChildStd_OUT_Rd);
			CloseHandle(g_hChildStd_OUT_Wr);
			return INVALID_HANDLE_VALUE;
		}

		startupInfo.hStdOutput = g_hChildStd_OUT_Wr;
		startupInfo.dwFlags |= STARTF_USESTDHANDLES;

		if (nh > _fileno(stdout))
		{
			osfhnd[_fileno(stdout)] = (intptr_t)g_hChildStd_OUT_Wr;
		}
	}

	if(ppipestderr)
	{
		if ( ! CreatePipe(&g_hChildStd_ERR_Rd, &g_hChildStd_ERR_Wr, &saAttr, 32767) ) 
		{
			LocalFree(lpReserved2);
			lpReserved2 = NULL;
			if(ppipestdin)
			{
				CloseHandle(g_hChildStd_IN_Rd);
				CloseHandle(g_hChildStd_IN_Wr);
			}
			if(ppipestdout)
			{
				CloseHandle(g_hChildStd_OUT_Rd);
				CloseHandle(g_hChildStd_OUT_Wr);
			}
			return INVALID_HANDLE_VALUE;
		}

		if (pSetHandleInformation && ! (*pSetHandleInformation)(g_hChildStd_ERR_Wr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) && GetLastError() != ERROR_CALL_NOT_IMPLEMENTED )
		{
			LocalFree(lpReserved2);
			lpReserved2 = NULL;
			if(ppipestdin)
			{
				CloseHandle(g_hChildStd_IN_Rd);
				CloseHandle(g_hChildStd_IN_Wr);
			}
			if(ppipestdout)
			{
				CloseHandle(g_hChildStd_OUT_Rd);
				CloseHandle(g_hChildStd_OUT_Wr);
			}
			CloseHandle(g_hChildStd_ERR_Rd);
			CloseHandle(g_hChildStd_ERR_Wr);
			return INVALID_HANDLE_VALUE;
		}

		startupInfo.hStdError = g_hChildStd_ERR_Wr;
		startupInfo.dwFlags |= STARTF_USESTDHANDLES;

		if (nh > _fileno(stderr))
		{
			osfhnd[_fileno(stderr)] = (intptr_t)g_hChildStd_ERR_Wr;
		}
	}

	if(!CreateProcessW(outBuf, 
						arg, 
						NULL, 
						NULL, 
						TRUE, 
						dwCreationFlags, 
						env, 
						NULL, 
						&startupInfo, 
						&processInformation))
	{
		LocalFree(lpReserved2);
		lpReserved2 = NULL;
		if(ppipestdin)
		{
			CloseHandle(g_hChildStd_IN_Rd);
			CloseHandle(g_hChildStd_IN_Wr);
		}
		if(ppipestdout)
		{
			CloseHandle(g_hChildStd_OUT_Rd);
			CloseHandle(g_hChildStd_OUT_Wr);
		}
		if(ppipestderr)
		{
			CloseHandle(g_hChildStd_ERR_Rd);
			CloseHandle(g_hChildStd_ERR_Wr);
		}
		return INVALID_HANDLE_VALUE;
	}

	LocalFree(lpReserved2);
	lpReserved2 = NULL;

	CloseHandle(processInformation.hThread);

	if(ppipestdin)
	{
		CloseHandle(g_hChildStd_IN_Rd);
		*ppipestdin = g_hChildStd_IN_Wr;
	}
	if(ppipestdout)
	{
		CloseHandle(g_hChildStd_OUT_Wr);
		*ppipestdout = g_hChildStd_OUT_Rd;
	}
	if(ppipestderr)
	{
		CloseHandle(g_hChildStd_ERR_Wr);
		*ppipestderr = g_hChildStd_ERR_Rd;
	}

	return processInformation.hProcess;
}

HANDLE __cdecl pwspawnv(
		HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
		LPCWSTR filename,
		LPCWSTR const FAR *argv
		)
{
	return pwspawnve(ppipestdin, ppipestdout, ppipestderr, filename, argv, NULL);
}

HANDLE __cdecl pwspawnlpe (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCWSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCWSTR FAR * args = argsBuf;
	LPCWSTR FAR * envp = NULL;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	envp = va_arg(list, LPCWSTR FAR *);
	res = pwspawnvpe (ppipestdin, ppipestdout, ppipestderr, filename, args, envp);

	va_end(list);

	return res;
}

HANDLE __cdecl pwspawnlp (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCWSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCWSTR FAR * args = argsBuf;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	res = pwspawnvp(ppipestdin, ppipestdout, ppipestderr, filename, args);

	va_end(list);

	return res;
}

HANDLE __cdecl pwspawnle (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCWSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCWSTR FAR * args = argsBuf;
	LPCWSTR FAR * envp = NULL;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	envp = va_arg(list, LPCWSTR FAR *);
	res = pwspawnve(ppipestdin, ppipestdout, ppipestderr, filename, args, envp);

	va_end(list);

	return res;
}

HANDLE __cdecl pwspawnl (
        HANDLE *ppipestdin,
		HANDLE *ppipestdout,
		HANDLE *ppipestderr,
        const LPCWSTR filename,
        const LPCWSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCWSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCWSTR FAR * args = argsBuf;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	res = pwspawnv(ppipestdin, ppipestdout, ppipestderr, filename, args);

	va_end(list);

	return res;
}
