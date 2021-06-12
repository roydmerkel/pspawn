#ifdef _WIN32

#include <io.h>
#include <fcntl.h>
#include <windows.h>

#if !defined(__cplusplus) && defined(__cplusplus_cli)
#define __cplusplus __cplusplus_cli
#endif

#if !defined(__cplusplus) && defined(__embedded_cplusplus)
#define __cplusplus __embedded_cplusplus
#endif

#define FOPEN           0x01    /* file handle open */
#define FEOFLAG         0x02    /* end of file has been encountered */
#ifdef _MAC
#define FWRONLY         0x04    /* file handle associated with write only file */
#define FLOCK           0x08    /* file has been successfully locked at least once */
#else  /* _MAC */
#define FCRLF           0x04    /* CR-LF across read buffer (in text mode) */
#define FPIPE           0x08    /* file handle refers to a pipe */
#endif  /* _MAC */
#ifdef _WIN32
#define FNOINHERIT      0x10    /* file handle opened _O_NOINHERIT */
#else  /* _WIN32 */
#define FRDONLY         0x10    /* file handle associated with read only file */
#endif  /* _WIN32 */

#define FAPPEND         0x20    /* file handle opened O_APPEND */
#define FDEV            0x40    /* file handle refers to device */
#define FTEXT           0x80    /* file handle is in text mode */

#if defined(__LCC__) && defined(WIN32)
	#if defined(__cplusplus)
	extern "C" {
	#endif
		extern FILE (*_imp___iob)[];
	#if defined(__cplusplus)
	}
	#endif
	
	#define _iob    (*_imp___iob)
	
	#define __iob(i) (&_iob[(i)])
	
	#define _osfhnd(i)  _get_osfhandle(i)

	static int _osfile(int i)
	{
		int ret = 0;
		int mode = -1;
		int flags = 0;
		mode = _setmode(i, O_BINARY);
		
		if(mode == -1)
		{
			return -1;
		}
		
		_setmode(i, mode);
		
		if(mode & _O_TEXT)
		{
			ret |= FTEXT;
			ret |= FCRLF;
		}
		
		if(mode & _O_NOINHERIT)
		{
			ret |= FNOINHERIT;
		}
		
		flags = __iob(i)->_flag;
		
		if((flags & _IOAPPEND) || (mode & _O_APPEND))
		{
			ret |= FAPPEND;
		}
		
		ret |= FOPEN;

		return ret;
	}
	
#elif defined (__MINGW32__) && defined (__MSVCRT__)
	// fcntl(fileno, F_GETFL) for Microsoft library
	// 'semi-documented' defines:
	#  define IOINFO_L2E          5
	#  define IOINFO_ARRAY_ELTS   (1 << IOINFO_L2E)
	#  define _pioinfo(i) ( __pioinfo[(i) >> IOINFO_L2E] + \
							((i) & (IOINFO_ARRAY_ELTS - 1)) )
							
	struct ioinfo {
		long osfhnd;    // the real os HANDLE
		char osfile;    // file handle flags
		char pipech;    // pipe buffer
		#  if defined (_MT)
		// multi-threaded locking
		int lockinitflag;
		CRITICAL_SECTION lock;
		#  endif
	};
		
	#if defined(__cplusplus)
	extern "C" {
	#endif
		__MINGW_IMPORT ioinfo * __pioinfo[];
	#if defined(__cplusplus)
	}
	#endif
	
#elif defined(_MSC_VER)
	#if !defined (_W64)
	#if !defined(__midl) && (defined(_X86_) || defined(_M_IX86)) && _MSC_VER >= 1300
	#define _W64 __w64
	#else  /* !defined(__midl) && (defined(_X86_) || defined(_M_IX86)) && _MSC_VER >= 1300 */
	#define _W64
	#endif  /* !defined(__midl) && (defined(_X86_) || defined(_M_IX86)) && _MSC_VER >= 1300 */
	#endif  /* !defined (_W64) */

	#ifndef _INTPTR_T_DEFINED
	#ifdef _WIN64
	typedef __int64             intptr_t;
	#else  /* _WIN64 */
	typedef _W64 int            intptr_t;
	#endif  /* _WIN64 */
	#define _INTPTR_T_DEFINED
	#endif  /* _INTPTR_T_DEFINED */

	#ifndef _UINTPTR_T_DEFINED
	#ifdef _WIN64
	typedef unsigned __int64    uintptr_t;
	#else  /* _WIN64 */
	typedef _W64 unsigned int   uintptr_t;
	#endif  /* _WIN64 */
	#define _UINTPTR_T_DEFINED
	#endif  /* _UINTPTR_T_DEFINED */

	#if _MSC_VER >= 1900
	typedef char lowio_text_mode;
	typedef char lowio_pipe_lookahead[3];

	typedef struct {
		CRITICAL_SECTION           lock;
		intptr_t                   osfhnd;          // underlying OS file HANDLE
		__int64                    startpos;        // File position that matches buffer start
		unsigned char              osfile;          // Attributes of file (e.g., open in text mode?)
		lowio_text_mode            textmode;
		lowio_pipe_lookahead       _pipe_lookahead;

		BYTE unicode : 1; // Was the file opened as unicode?
		BYTE utf8translations : 1; // Buffer contains translations other than CRLF
		BYTE dbcsBufferUsed : 1; // Is the dbcsBuffer in use?
		char    dbcsBuffer;           // Buffer for the lead byte of DBCS when converting from DBCS to Unicode
	} ioinfo;

	#define IOINFO_ARRAY_ELTS   (1 << IOINFO_L2E)

	/*
	* Definition of IOINFO_ARRAYS, maximum number of supported ioinfo arrays.
	*/
	#define IOINFO_ARRAYS       64

	#define _NHANDLE_           (IOINFO_ARRAYS * IOINFO_ARRAY_ELTS)

	#define IOINFO_L2E          6

	static __inline ioinfo ** setPioInfo();

	static ioinfo ** __pioinfo = NULL;
	static size_t pioinfo_extra = 0;

	static inline ioinfo* _tpioinfo(ioinfo ** pioinfo, int fd)
	{
		const size_t sizeof_ioinfo = sizeof(ioinfo) + pioinfo_extra;
		return (ioinfo*)((char*)pioinfo[fd >> IOINFO_L2E] +
			(fd & (IOINFO_ARRAY_ELTS - 1)) * sizeof_ioinfo);
	}

	#define _tosfhnd(pioinfo, i)  ( _tpioinfo(pioinfo, i)->osfhnd )

	static inline ioinfo* _pioinfo(int fd)
	{
		if (__pioinfo == NULL)
		{
			__pioinfo = setPioInfo();
		}
		return _tpioinfo(__pioinfo, fd);
	}

	#define _osfhnd(i)  ( _pioinfo(i)->osfhnd )

	#define _osfile(i)  ( _pioinfo(i)->osfile )

	#define _pipech(i)  ( (_pioinfo(i)->_pipe_lookahead[0]) )

	#define _pipech2(i)  ( &(_pioinfo(i)->_pipe_lookahead[1]) )

	#define _textmode(i) ( _pioinfo(i)->textmode )

	#define _tm_unicode(i) ( _pioinfo(i)->unicode )

	#define _startpos(i) ( _pioinfo(i)->startpos )

	#define _utf8translations(i) ( _pioinfo(i)->utf8translations )

	#define _dbcsBuffer(i) ( _pioinfo(i)->dbcsBuffer )

	#define _dbcsBufferUsed(i) ( _pioinfo(i)->dbcsBufferUsed )

	static __inline ioinfo ** setPioInfo()
	{
		HMODULE hUcrtbase = NULL;
		FARPROC func = NULL;
		LPSTR pFuncStart;
		LPSTR pFuncEnd;
		LPSTR pFunc;
		BOOL foundRet = FALSE;
		BOOL foundPio = FALSE;
		ioinfo ** ret = NULL;

	#if _DEBUG
		hUcrtbase = LoadLibrary(TEXT("ucrtbased.dll"));
	#else
		hUcrtbase = LoadLibrary(TEXT("ucrtbase.dll"));
	#endif
		if (!hUcrtbase)
			goto cleanup;
		func = GetProcAddress(hUcrtbase, "_isatty");
		if (!func)
			goto cleanup;
		pFuncStart = (LPSTR)func;
	#if _WIN64
		/* add         rsp,stacksize */
	#define FUNC_CLEAR_STACK "\x48\x83\xc4"
	#define FUNC_CLEAR_STACK_2 "\x48\x83\xc4"
		/* ret */
	#define FUNC_RET "\xC3"
	#define CLEAR_STACK_PARAM_BYTES 1
	#  ifdef _DEBUG
		/* lea rcx,[__pioinfo's addr in RIP-relative 32bit addr] */
	#   define PIOINFO_MARK "\x48\x8d\x0d"
	#  else
		/* lea rdx,[__pioinfo's addr in RIP-relative 32bit addr] */
	#   define PIOINFO_MARK "\x48\x8d\x15"
	#  endif
	#else
		/* mov         esp, ebp */
		/* pop         ebp */
	#define FUNC_CLEAR_STACK "\x8B\xE5\x5D"
	#define FUNC_CLEAR_STACK_2 "\x5F\x5E\x59\x5D"
		/* ret */
	#define FUNC_RET "\xC3"
	#define CLEAR_STACK_PARAM_BYTES 0
		/* mov eax,dword ptr [eax*4+__pioinfo] */
	#define PIOINFO_MARK "\x8B\x04\x85"
	#endif
		for (pFuncEnd = pFuncStart + CLEAR_STACK_PARAM_BYTES + sizeof FUNC_CLEAR_STACK - 1; pFuncEnd < pFuncStart + 0x300; pFuncEnd++)
		{
			if (memcmp(pFuncEnd, FUNC_RET, sizeof FUNC_RET - 1) == 0 && memcmp(pFuncEnd - CLEAR_STACK_PARAM_BYTES - sizeof FUNC_CLEAR_STACK + 1, FUNC_CLEAR_STACK, sizeof FUNC_CLEAR_STACK - 1) == 0)
			{
				pFuncEnd += (sizeof FUNC_RET - 2);
				foundRet = TRUE;
				break;
			}
			else if (memcmp(pFuncEnd, FUNC_RET, sizeof FUNC_RET - 1) == 0 && memcmp(pFuncEnd - CLEAR_STACK_PARAM_BYTES - sizeof FUNC_CLEAR_STACK_2 + 1, FUNC_CLEAR_STACK_2, sizeof FUNC_CLEAR_STACK_2 - 1) == 0)
			{
				pFuncEnd += (sizeof FUNC_RET - 2);
				foundRet = TRUE;
				break;
			}
		}
		if (!foundRet)
			goto cleanup;

		for (pFunc = pFuncEnd; pFunc >= pFuncStart; pFunc--)
		{
			if (memcmp(pFunc, PIOINFO_MARK, sizeof PIOINFO_MARK - 1) == 0)
			{
				pFunc += (sizeof PIOINFO_MARK - 1);
				foundPio = TRUE;
				break;
			}
		}

		if (!foundPio)
			goto cleanup;

	#if _WIN64
		DWORD rel = *(DWORD*)(pFunc);
		LPSTR rip = pFunc + sizeof(DWORD);
		ret = (ioinfo**)(rip + rel);
	#else
		ret = *(ioinfo***)(pFunc);
	#endif

		{
			int fd;

			fd = _open("NUL", O_RDONLY);
			for (pioinfo_extra = 0; pioinfo_extra <= 64; pioinfo_extra += sizeof(void *)) {
				if (_tosfhnd(ret, fd) == _get_osfhandle(fd)) {
					break;
				}
			}
			_close(fd);

			if (pioinfo_extra > 64) {
				/* could't find mystery fields or extra padding, abort! */
				ret = NULL;
			}
		}
	cleanup:
		if (func)
		{
			func = NULL;
		}

		if (hUcrtbase)
		{
			FreeLibrary(hUcrtbase);
		}
		return ret;
	}

	#elif _MSC_VER >= 1000
	/*
	 * Control structure for lowio file handles
	 */

	typedef struct {
		#if _MSC_VER >= 1300
		intptr_t osfhnd;/* underlying OS file HANDLE */
		#else
		long osfhnd;    /* underlying OS file HANDLE */
		#endif
		char osfile;    /* attributes of file (e.g., open in text mode?) */
		char pipech;    /* one char buffer for handles opened on pipes */
	#if (defined(_MT) && !defined (DLL_FOR_WIN32S)) || (_MSC_VER >= 1400)
		int lockinitflag;
		CRITICAL_SECTION lock;
	#endif  /* _MT */
	#if !defined(_SAFECRT_IMPL) && (_MSC_VER >= 1400)
		/* Not used in the safecrt downlevel. We do not define them, so we cannot use them accidentally */
		char textmode : 7;     /* __IOINFO_TM_ANSI or __IOINFO_TM_UTF8 or __IOINFO_TM_UTF16LE */
		char unicode : 1;      /* Was the file opened as unicode? */
		char pipech2[2];       /* 2 more peak ahead chars for UNICODE mode */
	  // defined for 2005 sp 1 vista (_MSC_FULL_VER=140050727), problem is sp1 also is also _MSC_FULL_VER=140050727
	  // luckily, __DECLARE_CPP_OVERLOAD_INLINE_FUNC_0_0_EX macro appears to have been added for sp1 vista.
	  #if (_MSC_VER > 1400) \
		|| (_MSC_VER == 1400 && (defined(_MSC_FULL_VER)) && (_MSC_FULL_VER > 140050727)) \
		|| (_MSC_VER == 1400 && (defined(_MSC_FULL_VER)) && (_MSC_FULL_VER == 140050727) && defined(__DECLARE_CPP_OVERLOAD_INLINE_FUNC_0_0_EX))	
		__int64 startpos;      /* File position that matches buffer start */
		BOOL utf8translations; /* Buffer contains translations other than CRLF*/
	  #endif
	  #if (_MSC_VER >= 1500)
		char dbcsBuffer;       /* Buffer for the lead byte of dbcs when converting from dbcs to unicode */
		BOOL dbcsBufferUsed;   /* Bool for the lead byte buffer is used or not */
	  #endif
	#endif  /* _SAFECRT_IMPL */
	}   ioinfo;

	/*
	 * Definition of IOINFO_L2E, the log base 2 of the number of elements in each
	 * array of ioinfo structs.
	 */
	#define IOINFO_L2E          5

	/*
	 * Definition of IOINFO_ARRAY_ELTS, the number of elements in ioinfo array
	 */
	#define IOINFO_ARRAY_ELTS   (1 << IOINFO_L2E)

	/*
	 * Definition of IOINFO_ARRAYS, maximum number of supported ioinfo arrays.
	 */
	#define IOINFO_ARRAYS       64

	#define _NHANDLE_           (IOINFO_ARRAYS * IOINFO_ARRAY_ELTS)

	/*
	 * Array of arrays of control structures for lowio files.
	 */
	#ifdef _SAFECRT_IMPL
	/* We need to get this from the downlevel DLL, even when we build safecrt.lib */
#if defined(__cplusplus)
	extern "C" {
#endif
	extern __declspec(dllimport) ioinfo * __pioinfo[];
#if defined(__cplusplus)
	}
#endif
	#else  /* _SAFECRT_IMPL */
	/*
	 * Array of arrays of control structures for lowio files.
	 */
#if defined(__cplusplus)
	extern "C" {
#endif
	extern _CRTIMP ioinfo * __pioinfo[];
#if defined(__cplusplus)
	}
#endif

	#endif  /* _SAFECRT_IMPL */

	/*
	 * Access macros for getting at an ioinfo struct and its fields from a
	 * file handle
	 */
	#define _pioinfo(i) ( __pioinfo[(i) >> IOINFO_L2E] + ((i) & (IOINFO_ARRAY_ELTS - \
								  1)) )
	#define _osfhnd(i)  ( (_pioinfo(i)) ? _pioinfo(i)->osfhnd : NULL )

	#define _osfile(i)  ( (_pioinfo(i)) ? _pioinfo(i)->osfile : 0)

	#define _pipech(i)  ( (_pioinfo(i)) ? _pioinfo(i)->pipech : 0)

	#if !defined(_SAFECRT_IMPL) && (_MSC_VER >= 1400)

	#define _pipech2(i)  ( (_pioinfo(i)) ? _pioinfo(i)->pipech2 : 0 )

	#define _textmode(i) ( (_pioinfo(i)) ? _pioinfo(i)->textmode : 0 )

	#define _tm_unicode(i) ( (_pioinfo(i)) ? _pioinfo(i)->unicode : 0 )

	#if (_MSC_VER > 1400) \
		|| (_MSC_VER == 1400 && (defined(_MSC_FULL_VER)) && (_MSC_FULL_VER > 140050727)) \
		|| (_MSC_VER == 1400 && (defined(_MSC_FULL_VER)) && (_MSC_FULL_VER == 140050727) && defined(__DECLARE_CPP_OVERLOAD_INLINE_FUNC_0_0_EX))

	#define _startpos(i) ( _pioinfo(i)->startpos )

	#define _utf8translations(i) ( _pioinfo(i)->utf8translations )

	#endif

	#if (_MSC_VER >= 1500)

	#define _dbcsBuffer(i) ( _pioinfo(i)->dbcsBuffer )

	#define _dbcsBufferUsed(i) ( _pioinfo(i)->dbcsBufferUsed )

	#endif

	#endif

	#else

	extern _CRTIMP long _osfhnd[];
	extern _CRTIMP char _osfile[];
	extern _CRTIMP char _pipech[];

	#define _osfhnd(i)  ( _osfhnd[i] )

	#define _osfile(i)  ( _osfile[i] )

	#endif

	#endif  /* _WIN32 */

	/*
	 * Current number of allocated ioinfo structures (_NHANDLE_ is the upper
	 * limit).
	 */
#if defined(__cplusplus)
	extern "C" {
#endif
	extern int _nhandle;
#if defined(__cplusplus)
	}
#endif

#else
#error unsupported.
#endif
