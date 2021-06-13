#include "pspawn.h"
#include "strFuncs.h"
#include "errFuncs.h"
#include "ioinfo.h"
#include <stdarg.h>
#include <errno.h>
#include <malloc.h>

#ifndef va_copy
#define va_copy(dest, src) ((dest) = (src))
#endif

#ifndef USHRT_MAX
#define USHRT_MAX 0x7FFF
#endif

#if _MSC_VER && _MSC_VER < 1000
typedef size_t SIZE_T;
#endif

#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES (DWORD)(-1)
#endif

typedef BOOL (*PSetHandleInformation)(HANDLE hObject, DWORD  dwMask, DWORD  dwFlags);
typedef BOOL (FAR * LPSetHandleInformation)(HANDLE hObject, DWORD  dwMask, DWORD  dwFlags);

static BOOL hasExt(LPCSTR arg)
{
	return (lstrrchrA(arg, '.') != NULL);
}

static BOOL isAbsolutePath(LPCSTR arg)
{
	return (lstrpbrkA(arg, "\\/") != NULL);
}

static BOOL nextPath(LPCSTR * pEnvPath, LPSTR outPath, DWORD bufSize)
{
	BOOL isQuote = FALSE;
	BOOL res = FALSE;
	const CHAR FAR * envPathPtr = NULL;
	CHAR FAR * outPathPtr = NULL;
	CHAR FAR * outPathEnd = NULL;

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

	if(**pEnvPath == '\0')
	{
		errno = EINVAL;
		return FALSE;
	}

	outPathPtr = outPath;
	outPathEnd = outPath + (bufSize / sizeof outPath[0]) - 1;

	for(envPathPtr=*pEnvPath; *envPathPtr != '\0' && outPathPtr < outPathEnd; envPathPtr++)
	{
		if(*envPathPtr == '"')
		{
			isQuote = !isQuote;
		}
		else if(!isQuote && *envPathPtr == ';')
		{
			break;
		}
		else
		{
			*outPathPtr = *envPathPtr;
			outPathPtr++;
		}
	}
	if(*envPathPtr == '\0')
	{
		if(*(envPathPtr - 1) != '\\' && *(envPathPtr - 1) != '/')
		{
			if(outPathPtr < outPathEnd)
			{
				*outPathPtr = '\\';
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
	else if(!isQuote && *envPathPtr == ';')
	{
		if(*(envPathPtr - 1) != '\\' && *(envPathPtr - 1) != '/')
		{
			if(outPathPtr < outPathEnd)
			{
				*outPathPtr = '\\';
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
	*outPathPtr = '\0';
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

static BOOL findExt(LPCSTR arg,  LPSTR outPath, DWORD bufSize)
{
	BOOL res = FALSE;
	const CHAR FAR * argPtr = NULL;
	CHAR * pathExtPtr = NULL;
	CHAR * pathExt = NULL;
#if _MSC_VER >= 1400
	size_t pathExtSize;
	BOOL pathExtAllocated = FALSE;
#endif
	CHAR FAR * outPathNullPtr = NULL;
	CHAR FAR * outPathPtr = NULL;
	CHAR FAR * outPathEndPtr = outPath + (bufSize / sizeof outPath[0]) - 1;

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
		if(GetFileAttributesA(arg) != INVALID_FILE_ATTRIBUTES)
		{
			// found.
			for(outPathPtr = outPath, argPtr = arg; *argPtr && outPathPtr < outPathEndPtr; outPathPtr++, argPtr++)
			{
				*outPathPtr = *argPtr;
			}

			*outPathPtr = '\0';
			if(*argPtr == '\0')
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
		if(_dupenv_s(&pathExt, &pathExtSize, "PATHEXT") == ENOMEM)
		{
			errno = ENOMEM;
			return FALSE;
		}
#else
		pathExt = getenv("PATHEXT");
#endif

		if(pathExt == NULL)
		{
			pathExt = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH";
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

		*outPathPtr = '\0';
		if(*argPtr == '\0')
		{
			outPathNullPtr = outPathPtr;

			for(pathExtPtr = pathExt; pathExtPtr && *pathExtPtr; pathExtPtr++)
			{
				if(*pathExtPtr == ';')
				{
					*outPathPtr = '\0';
					if(GetFileAttributesA(outPath) != INVALID_FILE_ATTRIBUTES)
					{
						res = TRUE;
						break;
					}
					dosmaperr(GetLastError());

					outPathPtr = outPathNullPtr;
					*outPathPtr = '\0';
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
				*outPathPtr = '\0';
				if(GetFileAttributesA(outPath) != INVALID_FILE_ATTRIBUTES)
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
					*outPathNullPtr = '\0';
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

static BOOL valistToArray(LPCSTR arg0, va_list *list, LPCSTR FAR * buf, DWORD bufSize)
{
	BOOL res = FALSE;
	DWORD size = 0;
	va_list cplist;
	LPCSTR arg;
	size_t cur = 0;
	LPCSTR FAR * arr = buf;
	
	errno = 0;

	if(list == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

	if(arg0 == NULL)
	{
		if(size + sizeof (LPSTR *) <= bufSize)
		{
			arr[cur++] = NULL;
			size += sizeof (LPSTR *);

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

		if(size + 2 * sizeof (LPSTR *) <= bufSize)
		{
			res = TRUE;
			arr[cur++] = arg0;
			arr[cur] = NULL;

			size += 2 * sizeof (LPSTR *);

			arg = va_arg(cplist, LPCSTR);
			while(arg)
			{
				if(size + sizeof (LPSTR) > bufSize)
				{
					errno = ENOMEM;
					res = FALSE;
					break;
				}

				arr[cur++] = arg;
				arr[cur] = NULL;

				size += sizeof (LPSTR *);

				arg = va_arg(cplist, LPCSTR);
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

static BOOL createEnv(LPCSTR const FAR * envp, CHAR FAR * buf, SIZE_T buf_size)
{
	CHAR FAR * pBuf = NULL;
	CHAR FAR * pBufEnd = NULL;
	CONST CHAR FAR * ppenv = NULL;
	CHAR FAR * pres = NULL;
	LPCSTR CONST * env = NULL;
	LPCSTR CONST * penv = NULL;
	LPCSTR CONST * penvp = NULL;
	BOOL found;
	CHAR sysRoot[] = "SystemRoot=";

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
		env = GetEnvironmentStringsArrayA();

		if(env)
		{
			// check for CWD vars: (=<dir>:= strings.) and SystemRoot.
			// Add to env string if they don't exist.
			for(penv = env; *penv; penv++)
			{
				if(**penv == '=' &&
					isalpha(*((*penv) + 1)) &&
					*((*penv) + 2) == ':' &&
					*((*penv) + 3) == '=')
				{
					found = FALSE;

					for(penvp = envp; *penvp; penvp++)
					{
						if(**penvp == '=' && 
							*((*penvp) + 1) == *((*penv) + 1) &&
							*((*penvp) + 2) == ':' &&
							*((*penvp) + 3) == '=')
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
						*pBuf = '\0';
						pBuf++;
					}
				}
				else if(lstrncmpiA(*penv, sysRoot, sizeof sysRoot / sizeof sysRoot[0] - 1) == 0)
				{
					found = FALSE;

					for(penvp = envp; *penvp; penvp++)
					{
						if(lstrncmpiA(*penvp, sysRoot, sizeof sysRoot / sizeof sysRoot[0] - 1) == 0)
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
						*pBuf = '\0';
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
				*pBuf = '\0';
				pBuf++;
			}

			if(pBuf == buf)
			{
				*pBuf = '\0';
				pBuf++;
			}

			*pBuf = '\0';
			pBuf++;

			LocalFree((HLOCAL)env);
		}
	}

	return TRUE;
}

static BOOL createArg(LPCSTR const FAR * argv, CHAR FAR * buf, SIZE_T buf_size)
{
	BOOL containsSpace;
	BOOL hasStartQuote;
	BOOL hasEndQuote;
	CHAR FAR * bufp = NULL;
	CHAR FAR * endBuf = NULL;
	LPCSTR FAR * argvp;
	CONST CHAR FAR * pargvp;

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

	for(argvp = (LPCSTR FAR *)argv; *argvp; argvp++)
	{
		if(argvp != argv)
		{
			if(bufp >= endBuf - 1)
			{
				errno = ENOMEM;
				return FALSE;
			}
			*bufp = ' ';
			bufp++;
		}

		containsSpace = FALSE;
		hasStartQuote = FALSE;
		hasEndQuote = FALSE;
		for(pargvp = *argvp; *pargvp; pargvp++)
		{
			if(pargvp == *argvp && *pargvp == '"')
			{
				hasStartQuote = TRUE;
			}
			else if(*(pargvp + 1) == '\0' && *pargvp == '"')
			{
				hasEndQuote = TRUE;
			}
			else if(*pargvp == ' ')
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
			*bufp = '"';
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
			*bufp = '"';
			bufp++;
		}
	}
	*bufp = '\0';
	bufp++;

	return TRUE;
}

static BOOL getLpReserved2(LPBYTE FAR *lpReserved2, WORD FAR *cbReserved2, WORD FAR *nh, CHAR FAR * FAR * osfile, intptr_t FAR * UNALIGNED FAR *osfhnd)
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

HANDLE __cdecl pspawnvpe(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv,
		LPCSTR const FAR *envp
		)
{
	HANDLE res = INVALID_HANDLE_VALUE;

	res = pspawnve(ppipestdin, ppipestdout, ppipestderr, filename, argv, envp);

	if((res == NULL || res == INVALID_HANDLE_VALUE) && errno == ENOENT && !isAbsolutePath(filename))
	{
		CHAR * path;
		CHAR * pathPtr;
		CHAR buf[MAX_PATH+1];
#if _MSC_VER >= 1400
		size_t pathSize;
#endif

#if _MSC_VER >= 1400
		if(_dupenv_s(&path, &pathSize, "PATH") == ENOMEM)
		{
			errno = ENOMEM;
			return FALSE;
		}
		pathPtr = path;
#else
		path = getenv("PATH");
		pathPtr = path;
#endif

		while(nextPath(&pathPtr, buf, MAX_PATH + 1))
		{
			if(lstrlenA(buf) + lstrlenA(filename) <= MAX_PATH)
			{
				lstrcatA(buf, filename);
				res = pspawnve(ppipestdin, ppipestdout, ppipestderr, buf, argv, envp);

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

HANDLE __cdecl pspawnvp(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv
		)
{
	return pspawnvpe(ppipestdin, ppipestdout, ppipestderr, filename, argv, NULL);
}

HANDLE __cdecl pspawnve(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv,
		LPCSTR const FAR *envp
		)
{
	CHAR outBuf[MAX_PATH + 1];
	CHAR env[0x7FFF];
	CHAR arg[0x7FFF];
	LPBYTE lpReserved2;
	WORD cbReserved2;
	WORD nh;
	CHAR FAR * osfile;
	intptr_t FAR * osfhnd;
	DWORD dwCreationFlags = 0;
	STARTUPINFOA startupInfo;
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

	memset(&startupInfo, '\0', sizeof (STARTUPINFOA));
	startupInfo.cb = sizeof (STARTUPINFOA);
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
		if (! CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) 
		{
			LocalFree(lpReserved2);
			lpReserved2 = NULL;
			return INVALID_HANDLE_VALUE;
		}

		if (pSetHandleInformation && ! (*pSetHandleInformation)(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0) && GetLastError() != ERROR_CALL_NOT_IMPLEMENTED )
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
		if ( ! CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0) ) 
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

		if (pSetHandleInformation && ! (*pSetHandleInformation)(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) && GetLastError() != ERROR_CALL_NOT_IMPLEMENTED )
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
		if ( ! CreatePipe(&g_hChildStd_ERR_Rd, &g_hChildStd_ERR_Wr, &saAttr, 0) ) 
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

		if (pSetHandleInformation && ! (*pSetHandleInformation)(g_hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0) && GetLastError() != ERROR_CALL_NOT_IMPLEMENTED )
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

	if(!CreateProcessA(outBuf, 
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
		int pf = -1;
		FILE *f = NULL;
		CloseHandle(g_hChildStd_IN_Rd);
		pf = _open_osfhandle((intptr_t)g_hChildStd_IN_Wr, _O_WRONLY | _O_TEXT);
		if(pf >= 0)
		{
			f = _fdopen(pf, "w");
			if(f != NULL)
			{
				*ppipestdin = f;
			}
			else
			{
				*ppipestdin = NULL;
				_close(pf);
			}
		}
		else
		{
			*ppipestdin = NULL;
			CloseHandle(g_hChildStd_IN_Wr);
		}
	}
	if(ppipestdout)
	{
		int pf = -1;
		FILE *f = NULL;
		CloseHandle(g_hChildStd_OUT_Wr);
		pf = _open_osfhandle((intptr_t)g_hChildStd_OUT_Rd, _O_RDONLY | _O_TEXT);
		if(pf >= 0)
		{
			f = _fdopen(pf, "r");
			if(f != NULL)
			{
				*ppipestdout = f;
			}
			else
			{
				*ppipestdout = NULL;
				_close(pf);
			}
		}
		else
		{
			*ppipestdout = NULL;
			CloseHandle(g_hChildStd_OUT_Rd);
		}
	}
	if(ppipestderr)
	{
		int pf = -1;
		FILE *f = NULL;
		CloseHandle(g_hChildStd_ERR_Wr);
		pf = _open_osfhandle((intptr_t)g_hChildStd_ERR_Rd, _O_RDONLY | _O_TEXT);
		if(pf >= 0)
		{
			f = _fdopen(pf, "r");
			if(f != NULL)
			{
				*ppipestderr = f;
			}
			else
			{
				*ppipestderr = NULL;
				_close(pf);
			}
		}
		else
		{
			*ppipestderr = NULL;
			CloseHandle(g_hChildStd_ERR_Rd);
		}
	}

	return processInformation.hProcess;
}

HANDLE __cdecl pspawnv(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCSTR filename,
		LPCSTR const FAR *argv
		)
{
	return pspawnve(ppipestdin, ppipestdout, ppipestderr, filename, argv, NULL);
}

HANDLE __cdecl pspawnlpe (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCSTR FAR * args = argsBuf;
	LPCSTR FAR * envp = NULL;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	envp = va_arg(list, LPCSTR FAR *);
	res = pspawnvpe (ppipestdin, ppipestdout, ppipestderr, filename, args, envp);

	va_end(list);

	return res;
}

HANDLE __cdecl pspawnlp (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCSTR FAR * args = argsBuf;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	res = pspawnvp(ppipestdin, ppipestdout, ppipestderr, filename, args);

	va_end(list);

	return res;
}

HANDLE __cdecl pspawnle (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCSTR FAR * args = argsBuf;
	LPCSTR FAR * envp = NULL;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	envp = va_arg(list, LPCSTR FAR *);
	res = pspawnve(ppipestdin, ppipestdout, ppipestderr, filename, args, envp);

	va_end(list);

	return res;
}

HANDLE __cdecl pspawnl (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCSTR filename,
        const LPCSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCSTR FAR * args = argsBuf;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	res = pspawnv(ppipestdin, ppipestdout, ppipestderr, filename, args);

	va_end(list);

	return res;
}
