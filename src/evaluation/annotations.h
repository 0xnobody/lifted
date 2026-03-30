#pragma once

#ifndef __has_attribute
#  define __has_attribute(x) 0
#endif

#define LIFTED_POLARIS_FUNCTION_ANNOTATION \
    "aliasaccess,boguscfg,customcc,flatten,indirectbr,indirectcall,linearmba,mergefunction,substitution"

#if defined(__clang__) && __has_attribute(annotate)
#  define LIFTED_POLARIS_FUNCTION_ANNOTATE \
    __attribute__((annotate(LIFTED_POLARIS_FUNCTION_ANNOTATION)))
#else
#  define LIFTED_POLARIS_FUNCTION_ANNOTATE
#endif

#define POLARIS_ANNOTATE LIFTED_POLARIS_FUNCTION_ANNOTATE