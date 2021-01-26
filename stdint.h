#ifndef STDINT__H
#define STDINT__H

typedef signed char int8_t;
typedef int int16_t;
typedef long int int32_t;
typedef unsigned char uint8_t;
typedef unsigned int uint16_t;

#ifdef __C51__
typedef unsigned long int uint32_t;
#else
typedef unsigned int uint32_t;
#endif

#endif
