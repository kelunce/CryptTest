#ifndef __CRYPT_H__
#define __CRYPT_H__

#include <windows.h>
#include <wincrypt.h>

typedef struct
{
	BLOBHEADER header;
	DWORD cbKeySize;
	BYTE rgbKeyData[8];
}KeyBlob;

LPSTR ConvertGBKToUtf8( LPSTR strGBK );

char* ConvertUtf8ToGB18030(const char *pText,int pLen);

void Base64Encode(BYTE *src, int src_len, BYTE *dst);

DWORD DesEncrypt(char* szEncrypt, char* szKey, BYTE* szOut, DWORD nOutLen);

char* Encrypt( char* sz_encrypt, char* sz_key, char* szOut, int nOutLen );

char* MD5(const char* szSrc,char* szHash);

char* SHA1(const char* szSrc,char* szHash);

#endif //__CRYPT_H__
