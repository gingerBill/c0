#ifndef C0_CONFIG_H
#define C0_CONFIG_H

#if defined(_WIN32)
# define C0_PLATFORM_WINDOWS
#elif defined(__linux__)
# define C0_PLATFORM_LINUX
#endif

#if defined(_MSC_VER)
# define C0_COMPILER_MSVC
#elif defined(__GNUC__)
# if defined(__clang__)
#   define C0_COMPILER_CLANG
# else
#   define C0_COMPILER_GCC
# endif
#endif

#if defined(__cplusplus)
#define C0_LIT(T, ...) (T{__VA_ARGS__})
#else
#define C0_LIT(T, ...) ((T){__VA_ARGS__})
#endif // defined(__cplusplus)

#if defined(__cplusplus)
#define C0_NORETURN [[noreturn]]
#else 
#define C0_NORETURN _Noreturn
#endif // defined(__cplusplus)

#if defined(__cplusplus)
# define C0_THREAD_LOCAL thread_local
#else
# define C0_THREAD_LOCAL _Thread_local
#endif // defined(__cplusplus)

#if defined(__cplusplus)
template<typename T>
const T *C0_ADDR_OF_RVAL(const T& ref) noexcept {
	return &ref;
}
#else
#	define C0_ADDR_OF_RVAL(ref) (&(ref))
#endif // defined(__cplusplus)

#if defined(__cplusplus)
#	define C0_ALIGNOF(T) alignof(T)
#else
#	define C0_ALIGNOF(T) _Alignof(T)
#endif // defined(__cplusplus)

#endif // C0_CONFIG_H