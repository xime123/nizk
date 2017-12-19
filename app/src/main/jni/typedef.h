#ifndef __HEADER_TYPEDEF_H__
#define __HEADER_TYPEDEF_H__

#define MR_PAIRING_BN
#define AES_SECURITY 128
#include "pairing_3.h"

/**/
typedef struct _NIZK_CIPHER
{
	int m;
	G1 g1;
}NIZK_List;
#endif