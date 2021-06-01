#include "pspawn.h"
#include "strFuncs.h"
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

static BOOL hasExt(LPCTSTR arg)
{
	return (lstrrchr(arg, _T('.')) != NULL);
}

static BOOL isAbsolutePath(LPCTSTR arg)
{
	return (lstrpbrk(arg, _T("\\/")) != NULL);
}

static BOOL nextPath(LPCTSTR * pEnvPath, LPTSTR outPath, DWORD bufSize)
{
	BOOL isQuote = FALSE;
	BOOL res = FALSE;
	const TCHAR FAR * envPathPtr = NULL;
	TCHAR FAR * outPathPtr = NULL;
	TCHAR FAR * outPathEnd = NULL;

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

	if(**pEnvPath == _T('\0'))
	{
		errno = EINVAL;
		return FALSE;
	}

	outPathPtr = outPath;
	outPathEnd = outPath + (bufSize / sizeof outPath[0]) - 1;

	for(envPathPtr=*pEnvPath; *envPathPtr != _T('\0') && outPathPtr < outPathEnd; envPathPtr++)
	{
		if(*envPathPtr == _T('"'))
		{
			isQuote = !isQuote;
		}
		else if(!isQuote && *envPathPtr == _T(';'))
		{
			break;
		}
		else
		{
			*outPathPtr = *envPathPtr;
			outPathPtr++;
		}
	}
	if(*envPathPtr == _T('\0'))
	{
		if(*(envPathPtr - 1) != _T('\\') && *(envPathPtr - 1) != _T('/'))
		{
			if(outPathPtr < outPathEnd)
			{
				*outPathPtr = _T('\\');
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
	else if(!isQuote && *envPathPtr == _T(';'))
	{
		if(*(envPathPtr - 1) != _T('\\') && *(envPathPtr - 1) != _T('/'))
		{
			if(outPathPtr < outPathEnd)
			{
				*outPathPtr = _T('\\');
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
	*outPathPtr = _T('\0');
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

static BOOL findExt(LPCTSTR arg,  LPTSTR outPath, DWORD bufSize)
{
	BOOL res = FALSE;
	const TCHAR FAR * argPtr = NULL;
	TCHAR * pathExtPtr = NULL;
	TCHAR * pathExt = NULL;
#if _MSC_VER >= 1400
	size_t pathExtSize;
	BOOL pathExtAllocated = FALSE;
#endif
	TCHAR FAR * outPathNullPtr = NULL;
	TCHAR FAR * outPathPtr = NULL;
	TCHAR FAR * outPathEndPtr = outPath + (bufSize / sizeof outPath[0]) - 1;

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
		if(_taccess(arg, 0) == 0)
		{
			// found.
			for(outPathPtr = outPath, argPtr = arg; *argPtr && outPathPtr < outPathEndPtr; outPathPtr++, argPtr++)
			{
				*outPathPtr = *argPtr;
			}

			*outPathPtr = _T('\0');
			if(*argPtr == _T('\0'))
			{
				res = TRUE;
			}
			else
			{
				errno = ENOMEM;
			}
		}
	}
	else
	{
#if _MSC_VER >= 1400
		if(_tdupenv_s(&pathExt, &pathExtSize, _T("PATHEXT")) == ENOMEM)
		{
			errno = ENOMEM;
			return FALSE;
		}
#else
		pathExt = _tgetenv(_T("PATHEXT"));
#endif
		if(pathExt == NULL)
		{
			pathExt = _T(".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH");
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

		*outPathPtr = _T('\0');
		if(*argPtr == _T('\0'))
		{
			outPathNullPtr = outPathPtr;

			for(pathExtPtr = pathExt; pathExtPtr && *pathExtPtr; pathExtPtr++)
			{
				if(*pathExtPtr == _T(';'))
				{
					*outPathPtr = _T('\0');
					if(_taccess(outPath, 0) == 0)
					{
						res = TRUE;
						break;
					}

					outPathPtr = outPathNullPtr;
					*outPathPtr = _T('\0');
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
				*outPathPtr = _T('\0');
				if(_taccess(outPath, 0) == 0)
				{
					res = TRUE;
				}
				else
				{
					if(errno == 0 || errno == ENOENT)
					{
						errno = ENOENT;
					}
					*outPathNullPtr = _T('\0');
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

static BOOL valistToArray(LPCTSTR arg0, va_list *list, LPCTSTR FAR * buf, DWORD bufSize)
{
	BOOL res = FALSE;
	DWORD size = 0;
	va_list cplist;
	LPCTSTR arg;
	size_t cur = 0;
	LPCTSTR FAR * arr = buf;
	
	errno = 0;

	if(list == NULL)
	{
		errno = EINVAL;
		return FALSE;
	}

	if(arg0 == NULL)
	{
		if(size + sizeof (LPTSTR *) <= bufSize)
		{
			arr[cur++] = NULL;
			size += sizeof (LPTSTR *);

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

		if(size + 2 * sizeof (LPTSTR *) <= bufSize)
		{
			res = TRUE;
			arr[cur++] = arg0;
			arr[cur] = NULL;

			size += 2 * sizeof (LPTSTR *);

			arg = va_arg(cplist, LPCTSTR);
			while(arg)
			{
				if(size + sizeof (LPTSTR) > bufSize)
				{
					errno = ENOMEM;
					res = FALSE;
					break;
				}

				arr[cur++] = arg;
				arr[cur] = NULL;

				size += sizeof (LPTSTR *);

				arg = va_arg(cplist, LPCTSTR);
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

static BOOL createEnv(LPCTSTR const FAR * envp, TCHAR FAR * buf, SIZE_T buf_size)
{
	TCHAR FAR * pBuf = NULL;
	TCHAR FAR * pBufEnd = NULL;
	CONST TCHAR FAR * ppenv = NULL;
	TCHAR FAR * pres = NULL;
	LPCTSTR CONST * env = NULL;
	LPCTSTR CONST * penv = NULL;
	LPCTSTR CONST * penvp = NULL;
	BOOL found;
	TCHAR sysRoot[] = _T("SystemRoot=");

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
		env = GetEnvironmentStringsArray();

		if(env)
		{
			// check for CWD vars: (=<dir>:= strings.) and SystemRoot.
			// Add to env string if they don't exist.
			for(penv = env; *penv; penv++)
			{
				if(**penv == _T('=') &&
					_istalpha(*((*penv) + 1)) &&
					*((*penv) + 2) == _T(':') &&
					*((*penv) + 3) == _T('='))
				{
					found = FALSE;

					for(penvp = envp; *penvp; penvp++)
					{
						if(**penvp == _T('=') && 
							*((*penvp) + 1) == *((*penv) + 1) &&
							*((*penvp) + 2) == _T(':') &&
							*((*penvp) + 3) == _T('='))
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
						*pBuf = _T('\0');
						pBuf++;
					}
				}
				else if(lstrncmpi(*penv, sysRoot, sizeof sysRoot / sizeof sysRoot[0] - 1) == 0)
				{
					found = FALSE;

					for(penvp = envp; *penvp; penvp++)
					{
						if(lstrncmpi(*penvp, sysRoot, sizeof sysRoot / sizeof sysRoot[0] - 1) == 0)
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
						*pBuf = _T('\0');
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
				*pBuf = _T('\0');
				pBuf++;
			}

			if(pBuf == buf)
			{
				*pBuf = _T('\0');
				pBuf++;
			}

			*pBuf = _T('\0');
			pBuf++;

			LocalFree((HLOCAL)env);
		}
	}

	return TRUE;
}

static BOOL createArg(LPCTSTR const FAR * argv, TCHAR FAR * buf, SIZE_T buf_size)
{
	BOOL containsSpace;
	BOOL hasStartQuote;
	BOOL hasEndQuote;
	TCHAR FAR * bufp = NULL;
	TCHAR FAR * endBuf = NULL;
	LPCTSTR FAR * argvp;
	CONST TCHAR FAR * pargvp;

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

	for(argvp = (LPCTSTR FAR *)argv; *argvp; argvp++)
	{
		if(argvp != argv)
		{
			if(bufp >= endBuf - 1)
			{
				errno = ENOMEM;
				return FALSE;
			}
			*bufp = _T(' ');
			bufp++;
		}

		containsSpace = FALSE;
		hasStartQuote = FALSE;
		hasEndQuote = FALSE;
		for(pargvp = *argvp; *pargvp; pargvp++)
		{
			if(pargvp == *argvp && *pargvp == _T('"'))
			{
				hasStartQuote = TRUE;
			}
			else if(*(pargvp + 1) == _T('\0') && *pargvp == _T('"'))
			{
				hasEndQuote = TRUE;
			}
			else if(*pargvp == _T(' '))
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
			*bufp = _T('"');
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
			*bufp = _T('"');
			bufp++;
		}
	}
	*bufp = _T('\0');
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
	lastHandle = _nhandle;
#elif _MSC_VER
	lastHandle = (((IOINFO_ARRAYS >> IOINFO_L2E) - 1) << IOINFO_L2E);
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
		ioinfo *info = _pioinfo(curHandle);

		if(info && (info->osfile & FOPEN) != 0 && (info->osfile & FNOINHERIT) == 0 &&
			info->osfhnd && info->osfhnd != (intptr_t)INVALID_HANDLE_VALUE)
		{
			*posfile = info->osfile;
			*posfhnd = info->osfhnd;
		}
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

HANDLE __cdecl ptspawnvpe(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv,
		LPCTSTR const FAR *envp
		)
{
	HANDLE res = INVALID_HANDLE_VALUE;

	res = ptspawnve(ppipestdin, ppipestdout, ppipestderr, filename, argv, envp);

	if((res == NULL || res == INVALID_HANDLE_VALUE) && errno == ENOENT && !isAbsolutePath(filename))
	{
		TCHAR * path;
		TCHAR * pathPtr;
		TCHAR buf[MAX_PATH+1];
#if _MSC_VER >= 1400
		size_t pathSize;
#endif

#if _MSC_VER >= 1400
		if(_tdupenv_s(&path, &pathSize, _T("PATH")) == ENOMEM)
		{
			errno = ENOMEM;
			return FALSE;
		}
		pathPtr = path;
#else
		path = _tgetenv(_T("PATH"));
		pathPtr = path;
#endif

		while(nextPath(&pathPtr, buf, MAX_PATH + 1))
		{
			if(lstrlen(buf) + lstrlen(filename) <= MAX_PATH)
			{
				lstrcat(buf, filename);
				res = ptspawnve(ppipestdin, ppipestdout, ppipestderr, buf, argv, envp);

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

HANDLE __cdecl ptspawnvp(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv
		)
{
	return ptspawnvpe(ppipestdin, ppipestdout, ppipestderr, filename, argv, NULL);
}

HANDLE __cdecl ptspawnve(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv,
		LPCTSTR const FAR *envp
		)
{
	TCHAR outBuf[MAX_PATH + 1];
	TCHAR env[0x7FFF];
	TCHAR arg[0x7FFF];
	LPBYTE lpReserved2;
	WORD cbReserved2;
	WORD nh;
	CHAR FAR * osfile;
	intptr_t FAR * osfhnd;
#ifdef  UNICODE
	DWORD dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
#else
	DWORD dwCreationFlags = 0;
#endif
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	SECURITY_ATTRIBUTES saAttr;
	HANDLE g_hChildStd_IN_Rd = NULL;
	HANDLE g_hChildStd_IN_Wr = NULL;
	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;
	HANDLE g_hChildStd_ERR_Rd = NULL;
	HANDLE g_hChildStd_ERR_Wr = NULL;

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

	memset(&startupInfo, '\0', sizeof (STARTUPINFO));
	startupInfo.cb = sizeof (STARTUPINFO);
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

		if ( ! SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0) )
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

		if ( ! SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) )
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

		if ( ! SetHandleInformation(g_hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0) )
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

	if(!CreateProcess(outBuf, 
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
#ifdef  UNICODE
		pf = _open_osfhandle((intptr_t)g_hChildStd_IN_Wr, _O_WRONLY | _O_WTEXT);
#else
		pf = _open_osfhandle((intptr_t)g_hChildStd_IN_Wr, _O_WRONLY | _O_TEXT);
#endif
		if(pf >= 0)
		{
			f = _tfdopen(pf, _T("w"));
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
#ifdef  UNICODE
		pf = _open_osfhandle((intptr_t)g_hChildStd_OUT_Rd, _O_RDONLY | _O_WTEXT);
#else
		pf = _open_osfhandle((intptr_t)g_hChildStd_OUT_Rd, _O_RDONLY | _O_TEXT);
#endif
		if(pf >= 0)
		{
			f = _tfdopen(pf, _T("r"));
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
#ifdef  UNICODE
		pf = _open_osfhandle((intptr_t)g_hChildStd_ERR_Rd, _O_RDONLY | _O_WTEXT);
#else
		pf = _open_osfhandle((intptr_t)g_hChildStd_ERR_Rd, _O_RDONLY | _O_TEXT);
#endif
		if(pf >= 0)
		{
			f = _tfdopen(pf, _T("r"));
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

HANDLE __cdecl ptspawnv(
		FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
		LPCTSTR filename,
		LPCTSTR const FAR *argv
		)
{
	return ptspawnve(ppipestdin, ppipestdout, ppipestderr, filename, argv, NULL);
}

HANDLE __cdecl ptspawnlpe (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCTSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCTSTR FAR * args = argsBuf;
	LPCTSTR FAR * envp = NULL;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	envp = va_arg(list, LPCTSTR FAR *);
	res = ptspawnvpe (ppipestdin, ppipestdout, ppipestderr, filename, args, envp);

	va_end(list);

	return res;
}

HANDLE __cdecl ptspawnlp (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCTSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCTSTR FAR * args = argsBuf;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	res = ptspawnvp(ppipestdin, ppipestdout, ppipestderr, filename, args);

	va_end(list);

	return res;
}

HANDLE __cdecl ptspawnle (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCTSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCTSTR FAR * args = argsBuf;
	LPCTSTR FAR * envp = NULL;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	envp = va_arg(list, LPCTSTR FAR *);
	res = ptspawnve(ppipestdin, ppipestdout, ppipestderr, filename, args, envp);

	va_end(list);

	return res;
}

HANDLE __cdecl ptspawnl (
        FILE **ppipestdin,
		FILE **ppipestdout,
		FILE **ppipestderr,
        const LPCTSTR filename,
        const LPCTSTR arg0,
        ...
        )
{
	HANDLE res = INVALID_HANDLE_VALUE;
	LPCTSTR argsBuf[1024];

	BOOL gotArgs = FALSE;
	LPCTSTR FAR * args = argsBuf;

	va_list list;
	va_start(list, arg0);

	gotArgs = valistToArray(arg0, &list, args, sizeof argsBuf);

	if(!gotArgs)
	{
		va_end(list);
		return INVALID_HANDLE_VALUE;
	}

	res = ptspawnv(ppipestdin, ppipestdout, ppipestderr, filename, args);

	va_end(list);

	return res;
}
