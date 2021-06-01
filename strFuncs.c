#include "strFuncs.h"

#ifndef MIN
#define MIN(A, B) (((A) < (B)) ? (A) : (B))
#endif

LPVOID lmemcpy(register LPVOID destination, register LPVOID source, size_t mem)
{
	register LPBYTE destByte = (LPBYTE)destination;
	register LPBYTE srcByte = (LPBYTE)source;
	LPBYTE srcEnd = srcByte + mem;

	for(; srcByte < srcEnd;)
	{
		*destByte++ = *srcByte++;
	}
	
	return destination;
}

LPCWSTR CONST FAR * GetEnvironmentStringsArrayW()
{
	SIZE_T count = 0;
	SIZE_T strSize = 0; 
	SIZE_T bufSize = 0;
	LPWSTR FAR * res = NULL;
	LPWCH penv = NULL;
	LPWCH env = GetEnvironmentStringsW();
	LPWSTR strPtr = NULL;
	LPWSTR FAR * ptrPtr = NULL;

	if(env == NULL)
	{
		return NULL;
	}

	for(penv = env; *penv || (!*penv && (penv == env || *(penv - 1))); penv++)
	{
		strSize++;
		if(!(*penv))
		{
			count++;
		}
	}

	bufSize = (count + 1) * sizeof (LPWSTR) + (strSize + 1) * sizeof (WCHAR);

	res = LocalAlloc(LPTR, bufSize);

	if(!res)
	{
		FreeEnvironmentStringsW(env);
		return NULL;
	}

	ptrPtr = (LPWSTR FAR *)res;
	strPtr = (LPWSTR)(ptrPtr + (count + 1));

	lmemcpy(strPtr, env, strSize * sizeof (WCHAR));

	for(; *strPtr != L'\0';)
	{
		*ptrPtr = strPtr;
		ptrPtr++;

		while(*strPtr != L'\0')
		{
			*strPtr++;
		}
		*strPtr++;
	}
	FreeEnvironmentStringsW(env);
	return res;
}

LPCSTR CONST FAR * GetEnvironmentStringsArrayA()
{
	SIZE_T count = 0;
	SIZE_T strSize = 0; 
	SIZE_T bufSize = 0;
	SIZE_T mcharStrSize = 0;
	LPCSTR FAR * res = NULL;
	LPWCH penv = NULL;
	LPWCH env = GetEnvironmentStringsW();
	LPSTR strPtr = NULL;
	LPSTR FAR *ptrPtr = NULL;

	if(env == NULL)
	{
		return NULL;
	}

	for(penv = env; *penv || (!*penv && (penv == env || *(penv - 1))); penv++)
	{
		strSize++;
		if(!(*penv))
		{
			count++;
		}
	}

	mcharStrSize = WideCharToMultiByte(CP_ACP,0, env, (int)strSize, NULL, 0, NULL, NULL);

	bufSize = (count + 1) * sizeof (LPCSTR) + (mcharStrSize + 1) * sizeof (CHAR);

	res = LocalAlloc(LPTR, bufSize);

	if(!res)
	{
		FreeEnvironmentStringsW(env);
		return NULL;
	}

	ptrPtr = (LPSTR FAR *)res;
	strPtr = (LPSTR)(ptrPtr + (count + 1));

	if(!WideCharToMultiByte(CP_ACP,0, env, (int)strSize, (LPSTR)strPtr, (int)(mcharStrSize) + 1, NULL, NULL))
	{
		FreeEnvironmentStringsW(env);
		LocalFree((HLOCAL)res);
		res = NULL;
		return NULL;
	}

	for(; *strPtr != '\0';)
	{
		*ptrPtr = strPtr;
		ptrPtr++;

		while(*strPtr != '\0')
		{
			*strPtr++;
		}
		*strPtr++;
	}
	FreeEnvironmentStringsW(env);
	return res;
}

// CompareString and CompareStringW are undefined on NT 3.1
#ifndef CompareString
	#ifdef  UNICODE
		#define CompareString CompareStringW
	#else   /* UNICODE */
		#define CompareString CompareStringA
	#endif /* UNICODE */
	static inline int CompareStringA(LCID lcid, DWORD fdwStyle, LPCSTR lpString1, int cch1, LPCSTR lpString2, int cch2)
	{
		int lpString1Len = ((lpString1 == NULL) ? 0 : lstrlen(lpString1));
		int lpString2Len = ((lpString2 == NULL) ? 0 : lstrlen(lpString2));

		int cch1BufLength;
		int cch2BufLength;

		int i;
		int ret;

		LPWSTR string1;
		LPWSTR string2;

		if(cch1 < 0)
		{
			cch1BufLength = lpString1Len;
		}
		else
		{
			cch1BufLength = MIN(lpString1Len + 1, cch1);
		}

		if(cch2 < 0)
		{
			cch2BufLength = lpString2Len;
		}
		else
		{
			cch2BufLength = MIN(lpString2Len + 1, cch2);
		}

		string1 = (LPWSTR)LocalAlloc(LPTR, cch1BufLength * sizeof (WCHAR));

		if(string1 == NULL)
		{
			return 0;
		}

		string2 = (LPWSTR)LocalAlloc(LPTR, cch2BufLength * sizeof (WCHAR));

		if(string2 == NULL)
		{
			DWORD err = GetLastError();
			LocalFree(string1);
			SetLastError(err);

			return 0;
		}

		for(i = 0; i < cch1BufLength; i++)
		{
			string1[i] = lpString1[i];
		}

		for(i = 0; i < cch2BufLength; i++)
		{
			string2[i] = lpString2[i];
		}

		ret = CompareStringW(lcid, fdwStyle, string1, cch1, string2, cch2);

		LocalFree(string1);
		LocalFree(string2);

		return ret;
	}
#endif

const CHAR * FAR lstrchrA(LPCSTR str, WORD c)
{
	const CHAR FAR * pStr = NULL;

	if(str == NULL)
	{
		return NULL;
	}

	for(pStr = str; *pStr != '\0'; pStr++)
	{
		if((WORD)(*pStr) == c)
		{
			return pStr;
		}
	}

	return NULL;
}

const WCHAR * FAR lstrchrW(LPCWSTR str, WORD c)
{
	const WCHAR FAR * pStr = NULL;

	if(str == NULL)
	{
		return NULL;
	}

	for(pStr = str; *pStr != '\0'; pStr++)
	{
		if((WORD)(*pStr) == c)
		{
			return pStr;
		}
	}

	return NULL;
}

const CHAR * FAR lstrrchrA(LPCSTR str, WORD c)
{
	const CHAR FAR * pStr = NULL;
	size_t len = 0;

	if(str == NULL)
	{
		return NULL;
	}

	len = lstrlenA(str);

	for(pStr = str + len - 1; pStr >= str; pStr--)
	{
		if((WORD)(*pStr) == c)
		{
			return pStr;
		}
	}

	return NULL;
}

const WCHAR * FAR lstrrchrW(LPCWSTR str, WORD c)
{
	const WCHAR FAR * pStr = NULL;
	size_t len = 0;

	if(str == NULL)
	{
		return NULL;
	}

	len = lstrlenW(str);

	for(pStr = str + len - 1; pStr >= str; pStr--)
	{
		if((WORD)(*pStr) == c)
		{
			return pStr;
		}
	}

	return NULL;
}

const CHAR * FAR lstrstrA(LPCSTR str, LPCSTR strSearch)
{
	const CHAR * pStr = NULL;
	const CHAR * pStrEnd = NULL;
	int cchStr = 0;
	int cchStrSearch = 0;
	size_t strLen = 0;
	size_t strSearchLen = 0;

	if(str == NULL)
	{
		return NULL;
	}
	else if(strSearch == NULL)
	{
		return NULL;
	}

	strLen = lstrlenA(str);
	strSearchLen = lstrlenA(strSearch);

	if(strSearchLen > strLen)
	{
		return NULL;
	}

	pStrEnd = str + strLen - strSearchLen + 1;

	cchStrSearch = (int)strSearchLen;
	for(pStr = str, cchStr = (int)strLen; pStr < pStrEnd; pStr++, cchStr--)
	{
		if(CompareStringA(GetThreadLocale(), 0, pStr, MIN(cchStr, cchStrSearch), strSearch, cchStrSearch) == CSTR_EQUAL)
		{
			return pStr;
		}
	}

	return NULL;
}

const WCHAR * FAR lstrstrW(LPCWSTR str, LPCWSTR strSearch)
{
	const WCHAR * pStr = NULL;
	const WCHAR * pStrEnd = NULL;
	int cchStr = 0;
	int cchStrSearch = 0;
	size_t strLen = 0;
	size_t strSearchLen = 0;

	if(str == NULL)
	{
		return NULL;
	}
	else if(strSearch == NULL)
	{
		return NULL;
	}

	strLen = lstrlenW(str);
	strSearchLen = lstrlenW(strSearch);

	if(strSearchLen > strLen)
	{
		return NULL;
	}

	pStrEnd = str + strLen - strSearchLen + 1;

	cchStrSearch = (int)strSearchLen;
	for(pStr = str, cchStr = (int)strLen; pStr < pStrEnd; pStr++, cchStr--)
	{
		if(CompareStringW(GetThreadLocale(), 0, pStr, MIN(cchStr, cchStrSearch), strSearch, cchStrSearch) == CSTR_EQUAL)
		{
			return pStr;
		}
	}

	return NULL;
}

const CHAR * FAR lstrrstrA(LPCSTR str, LPCSTR strSearch)
{
	const CHAR * pStr = NULL;
	int cchStr = 0;
	int cchStrSearch = 0;
	size_t strLen = 0;
	size_t strSearchLen = 0;

	if(str == NULL)
	{
		return NULL;
	}
	else if(strSearch == NULL)
	{
		return NULL;
	}

	strLen = lstrlenA(str);
	strSearchLen = lstrlenA(strSearch);

	if(strSearchLen > strLen)
	{
		return NULL;
	}

	cchStrSearch = (int)strSearchLen;
	for(pStr = str + strLen - strSearchLen, cchStr = (int)strSearchLen; pStr >= str; pStr--, cchStr++)
	{
		if(CompareStringA(GetThreadLocale(), 0, pStr, MIN(cchStr, cchStrSearch), strSearch, cchStrSearch) == CSTR_EQUAL)
		{
			return pStr;
		}
	}

	return NULL;
}

const WCHAR * FAR lstrrstrW(LPCWSTR str, LPCWSTR strSearch)
{
	const WCHAR * pStr = NULL;
	int cchStr = 0;
	int cchStrSearch = 0;
	size_t strLen = 0;
	size_t strSearchLen = 0;

	if(str == NULL)
	{
		return NULL;
	}
	else if(strSearch == NULL)
	{
		return NULL;
	}

	strLen = lstrlenW(str);
	strSearchLen = lstrlenW(strSearch);

	if(strSearchLen > strLen)
	{
		return NULL;
	}

	cchStrSearch = (int)strSearchLen;
	for(pStr = str + strLen - strSearchLen, cchStr = (int)strSearchLen; pStr >= str; pStr--, cchStr++)
	{
		if(CompareStringW(GetThreadLocale(), 0, pStr, MIN(cchStr, cchStrSearch), strSearch, cchStrSearch) == CSTR_EQUAL)
		{
			return pStr;
		}
	}

	return NULL;
}

const CHAR * FAR lstrpbrkA(LPCSTR str, LPCSTR set)
{
	const CHAR * FAR pStr;

	if(str == NULL)
	{
		return NULL;
	}

	for(pStr = str; *pStr != '\0'; pStr++)
	{
		if(lstrchrA(set, *pStr))
		{
			return pStr;
		}
	}

	return NULL;
}

const WCHAR * FAR lstrpbrkW(LPCWSTR str, LPCWSTR set)
{
	const WCHAR * FAR pStr;

	if(str == NULL)
	{
		return NULL;
	}

	for(pStr = str; *pStr != '\0'; pStr++)
	{
		if(lstrchrW(set, *pStr))
		{
			return pStr;
		}
	}

	return NULL;
}

int lstrncmpA(LPCSTR string1, LPCSTR string2, size_t count)
{
	switch(CompareStringA(GetThreadLocale(), 0, string1, (int)MIN((size_t)lstrlenA(string1), count), string2, (int)MIN((size_t)lstrlenA(string2), count)))
	{
		case CSTR_LESS_THAN:
			return -1;
			break;
		case CSTR_EQUAL:
			return 0;
			break;
		case CSTR_GREATER_THAN:
		default:
			return 1;
			break;
	}
}

int lstrncmpW(LPCWSTR string1, LPCWSTR string2, size_t count)
{
	switch(CompareStringW(GetThreadLocale(), 0, string1, (int)MIN((size_t)lstrlenW(string1), count), string2, (int)MIN((size_t)lstrlenW(string2), count)))
	{
		case CSTR_LESS_THAN:
			return -1;
			break;
		case CSTR_EQUAL:
			return 0;
			break;
		case CSTR_GREATER_THAN:
		default:
			return 1;
			break;
	}
}

int lstrncmpiA(LPCSTR string1, LPCSTR string2, size_t count)
{
	switch(CompareStringA(GetThreadLocale(), NORM_IGNORECASE, string1, (int)MIN((size_t)lstrlenA(string1), count), string2, (int)MIN((size_t)lstrlenA(string2), count)))
	{
		case CSTR_LESS_THAN:
			return -1;
			break;
		case CSTR_EQUAL:
			return 0;
			break;
		case CSTR_GREATER_THAN:
		default:
			return 1;
			break;
	}
}

int lstrncmpiW(LPCWSTR string1, LPCWSTR string2, size_t count)
{
	switch(CompareStringW(GetThreadLocale(), NORM_IGNORECASE, string1, (int)MIN((size_t)lstrlenW(string1), count), string2, (int)MIN((size_t)lstrlenW(string2), count)))
	{
		case CSTR_LESS_THAN:
			return -1;
			break;
		case CSTR_EQUAL:
			return 0;
			break;
		case CSTR_GREATER_THAN:
		default:
			return 1;
			break;
	}
}
