#ifndef C0_CONFIG_H
#define C0_CONFIG_H

#if defined(_WIN32)
# define C0_PLATFORM_WINDOWS 1
#elif defined(__linux__)
# define C0_PLATFORM_LINUX 1
#endif

#if defined(__cplusplus)
#define C0_LIT(T, ...) (T{__VA_ARGS__})
#else
#define C0_LIT(T, ...) ((T){__VA_ARGS__})
#endif

#endif // C0_CONFIG_H