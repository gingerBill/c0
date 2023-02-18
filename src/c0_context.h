#ifndef C0_CONTEXT_H
#define C0_CONTEXT_H
#include <stdarg.h> // va_list

#include "c0_allocator.h" // C0Allocator
#include "c0_logger.h" // C0Logger

typedef struct C0Context C0Context;

struct C0Context {
	void (*assert_cb)(const char *file, const char *function, int line, const char *condition, const char *msg, va_list va);
	const C0Allocator *allocator;
	const C0Logger *logger;
};

extern const C0Context C0_DEFAULT_CONTEXT;

extern _Thread_local C0Context c0_context;

static inline void c0_infof_(const C0SourceLocation *location, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	c0_context.logger->log(location, C0_LOG_INFO, fmt, va);
	va_end(va);
}

static inline void c0_warningf_(const C0SourceLocation *location, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	c0_context.logger->log(location, C0_LOG_WARNING, fmt, va);
	va_end(va);
}

static inline void c0_errorf_(const C0SourceLocation *location, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	c0_context.logger->log(location, C0_LOG_ERROR, fmt, va);
	va_end(va);
}

#define c0_infof(...) \
	c0_infof_(&C0_SOURCE_LOCATION, __VA_ARGS__)

#define c0_warningf(...) \
	c0_warningf_(&C0_SOURCE_LOCATION, __VA_ARGS__)

#define c0_errorf(...) \
	c0_errorf_(&C0_SOURCE_LOCATION, __VA_ARGS__)

void *c0_allocate_uninitialized(usize bytes);
void *c0_allocate_zeroed(usize bytes);
void *c0_reallocate(void *data, usize bytes);
void c0_deallocate(void *data);
void c0_deallocate_all(void);

#define c0_new(T) \
	((T*)c0_allocate_zeroed(sizeof(T)))

#endif // C0_CONTEXT_H