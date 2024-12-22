#include <windows.h>
#include <tchar.h>
#include <wchar.h>

LPCSTR CONST FAR * GetEnvironmentStringsArrayA(void);
LPCWSTR CONST FAR * GetEnvironmentStringsArrayW(void);

#ifdef  UNICODE
	#define GetEnvironmentStringsArray GetEnvironmentStringsArrayW
#else
	#define GetEnvironmentStringsArray GetEnvironmentStringsArrayA
#endif

LPVOID lmemcpy(register LPVOID destination, register LPVOID source, size_t mem);

const CHAR * FAR lstrchrA(LPCSTR str, WORD c);
const WCHAR * FAR lstrchrW(LPCWSTR str, WORD c);
const CHAR * FAR lstrrchrA(LPCSTR str, WORD c);
const WCHAR * FAR lstrrchrW(LPCWSTR str, WORD c);
const CHAR * FAR lstrstrA(LPCSTR str, LPCSTR strSearch);
const WCHAR * FAR lstrstrW(LPCWSTR str, LPCWSTR strSearch);
const CHAR * FAR lstrrstrA(LPCSTR str, LPCSTR strSearch);
const WCHAR * FAR lstrrstrW(LPCWSTR str, LPCWSTR strSearch);
const CHAR * FAR lstrpbrkA(LPCSTR str, LPCSTR set);
const WCHAR * FAR lstrpbrkW(LPCWSTR str, LPCWSTR set);

int lstrncmpA(LPCSTR string1, LPCSTR string2, size_t count);
int lstrncmpW(LPCWSTR string1, LPCWSTR string2, size_t count);
int lstrncmpiA(LPCSTR string1, LPCSTR string2, size_t count);
int lstrncmpiW(LPCWSTR string1, LPCWSTR string2, size_t count);

#ifdef  UNICODE
	#define lstrstr lstrstrW
	#define lstrrstr lstrrstrW
	#define lstrchr lstrchrW
	#define lstrrchr lstrrchrW
	#define lstrpbrk lstrpbrkW
	#define lstrncmp lstrncmpW
	#define lstrncmpi lstrncmpiW
#else   /* UNICODE */
	#define lstrstr lstrstrA
	#define lstrrstr lstrrstrA
	#define lstrchr lstrchrA
	#define lstrrchr lstrrchrA
	#define lstrpbrk lstrpbrkA
	#define lstrncmp lstrncmpA
	#define lstrncmpi lstrncmpiA
#endif /* UNICODE */
