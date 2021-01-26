#ifndef STDINT__H
#define STDINT__H

typedef unsigned char uint8_t;

#ifdef __C51__
typedef unsigned long int uint32_t;
#else
typedef unsigned int uint32_t;
#endif

#endif
