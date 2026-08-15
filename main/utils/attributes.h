/*
 * Compiler attributes used across the project.
 */

#ifndef KERN_ATTRIBUTES_H
#define KERN_ATTRIBUTES_H

/*
 * KERN_WARN_UNUSED_RESULT - the compiler warns at any call site that discards
 * the return value. Applied to functions that report failure through their
 * return value and nothing else, and to queries whose answer is the only
 * reason to call them. The build turns the warning into an error.
 *
 * NOTE: a (void) cast does not suppress this under GCC. To ignore a result
 * deliberately, consume it with `if (call()) { }` and say why.
 */
#if defined(__GNUC__) || defined(__clang__)
#define KERN_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#define KERN_WARN_UNUSED_RESULT
#endif

#endif // KERN_ATTRIBUTES_H
