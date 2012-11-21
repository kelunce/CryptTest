#include <stdio.h>
#include "crypt.h"

#pragma comment( lib, "Advapi32.lib" )

LPSTR ConvertGBKToUtf8( LPSTR strGBK )
{
	int len = MultiByteToWideChar(CP_ACP, 0, (LPSTR)strGBK, -1, NULL,0);
	unsigned short * wszUtf8 = new unsigned short[len+1];
	memset( wszUtf8, 0, len * 2 + 2 );
	MultiByteToWideChar( CP_ACP, 0, (LPSTR)strGBK, -1, (LPWSTR)wszUtf8, len );

	len = WideCharToMultiByte( CP_UTF8, 0, (LPCWSTR)wszUtf8, -1, NULL, 0, NULL, NULL );
	char *szUtf8=new char[len + 1];
	memset( szUtf8, 0, len + 1 );
	WideCharToMultiByte ( CP_UTF8, 0, (LPCWSTR)wszUtf8, -1, szUtf8, len, NULL,NULL );

	return szUtf8;
}

void UTF8ToUnicode(wchar_t* pOut,const char *pText)  
{  
	char* uchar = (char *)pOut;  
	uchar[1] = ((pText[0]&0x0F)<<4)+((pText[1]>>2)&0x0F);  
	uchar[0] = ((pText[1]&0x03)<<6)+(pText[2]&0x3F);  
}  

void UnicodeToGB18030(char* pOut,unsigned short* uData)   
{  
	::WideCharToMultiByte(CP_ACP,NULL,LPCWSTR(uData),1,pOut,sizeof(WCHAR),NULL,NULL);  
}

char* ConvertUtf8ToGB18030(const char *pText,int pLen)   
{      
	char * newBuf = new char[pLen];  
	char Ctemp[4];  
	memset(Ctemp,0,4);   
	int i =0;  
	int j = 0;   

	while(i < pLen)      
	{      
		if(pText[i] > 0)          
		{          
			newBuf[j++] = pText[i++];          
		}  
		else      
		{      
			wchar_t Wtemp;  
			UTF8ToUnicode(&Wtemp,pText+i);  
			UnicodeToGB18030(Ctemp,(unsigned short*)&Wtemp);  
			newBuf[j] = Ctemp[0];  
			newBuf[j+1] = Ctemp[1];  
			i+= 3;  
			j+= 2;  
		}  
	}  
	strcpy(&newBuf[j],"/0");  
	return newBuf;  
}

void Base64Encode(BYTE *src, int src_len, BYTE *dst)
{
	int i = 0, j = 0;
	char base64_map[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for (; i < src_len - src_len % 3; i += 3) {
		dst[j++] = base64_map[(src[i] >> 2) & 0x3F];
		dst[j++] = base64_map[((src[i] << 4) & 0x30) + ((src[i + 1] >> 4) & 0xF)];
		dst[j++] = base64_map[((src[i + 1] << 2) & 0x3C) + ((src[i + 2] >> 6) & 0x3)];
		dst[j++] = base64_map[src[i + 2] & 0x3F];
	}

	if (src_len % 3 == 1) {
		dst[j++] = base64_map[(src[i] >> 2) & 0x3F];
		dst[j++] = base64_map[(src[i] << 4) & 0x30];
		dst[j++] = '=';
		dst[j++] = '=';
	}else if (src_len % 3 == 2) {
		dst[j++] = base64_map[(src[i] >> 2) & 0x3F];
		dst[j++] = base64_map[((src[i] << 4) & 0x30) + ((src[i + 1] >> 4) & 0xF)];
		dst[j++] = base64_map[(src[i + 1] << 2) & 0x3C];
		dst[j++] = '=';
	}

	dst[j] = '\0';
}

DWORD DesEncrypt(char* szEncrypt, char* szKey, BYTE* szOut, DWORD nOutLen)
{
	char* sz_utf8_buff = ConvertGBKToUtf8( szEncrypt );

	DWORD dwEncrypt = strlen(sz_utf8_buff);

	if( szOut == NULL || \
		nOutLen < dwEncrypt + 8 - (dwEncrypt % 8) || \
		strlen( szKey ) < 8)
		return 0;
	memcpy(szOut, sz_utf8_buff, dwEncrypt);

	// init
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hSessionKey = NULL;
	BOOL bResult = TRUE;

	KeyBlob blob;
	blob.header.bType = PLAINTEXTKEYBLOB;
	blob.header.bVersion = CUR_BLOB_VERSION;
	blob.header.reserved = 0;
	blob.header.aiKeyAlg = CALG_DES;
	blob.cbKeySize = 8;
	memcpy(blob.rgbKeyData, szKey, 8);

	BYTE IV[9] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef};

	// start
	CryptAcquireContext(&hProv,NULL, MS_DEF_PROV, PROV_RSA_FULL,0);
	CryptImportKey(hProv, (BYTE*)&blob, sizeof(blob), 0, 0, &hSessionKey);
	CryptSetKeyParam(hSessionKey, KP_IV, (BYTE*)IV, 0);

	// Do
	CryptEncrypt(hSessionKey, NULL, TRUE, 0, (BYTE*)szOut, &dwEncrypt, nOutLen);

	// Clean
	CryptDestroyKey(hSessionKey);
	CryptReleaseContext(hProv, 0);
	delete sz_utf8_buff;

	return dwEncrypt;
}

char* Encrypt( char* sz_encrypt, char* sz_key, char* szOut, int nOutLen )
{
	BYTE szDes[1024] = {0};

	// do Des crypt
	DWORD dwRet = DesEncrypt( sz_encrypt, sz_key, szDes, 1024 );

	// do base64
	int nLen = dwRet;//strlen( (char*)szDes );
	int nLenOut = nLen * 4 / 3;
	if (nLenOut+1 > nOutLen)
		return NULL;
	memset( szOut, 0, nLenOut+1 );
	Base64Encode( szDes, nLen, (BYTE*)szOut );

	return szOut;
}

char* MD5(const char* szSrc,char* szHash)
{
	BOOL bResult = TRUE;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD dwLength;
	BYTE szHashData[128];
	DWORD dwHashLen = 16;

	// Get handle to user default provider.
	if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		//如果密钥容器不存在,创建这个密钥容器[LCM 2012/11/21  16:41]
		if(GetLastError() == NTE_BAD_KEYSET)
		{
			if(!CryptAcquireContext(&hProv,	NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				return NULL;
		}
		else
		{
			return NULL;
		}
	}

	// Create hash object.
	if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		// Hash password string.
		dwLength = strlen(szSrc);
		if (CryptHashData(hHash, (BYTE *)szSrc, dwLength, 0))
		{
			CryptGetHashParam(hHash,HP_HASHVAL,szHashData,&dwHashLen,0);
		}
		else
		{
			// Error during CryptHashData!
			bResult = FALSE;
		}
		CryptDestroyHash(hHash); // Destroy session key.
	}
	else
	{
		// Error during CryptCreateHash!
		bResult = FALSE;
	}
	CryptReleaseContext(hProv, 0);


	if (bResult)
	{
		sprintf(szHash, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			szHashData[0],szHashData[1],szHashData[2],szHashData[3],
			szHashData[4],szHashData[5],szHashData[6],szHashData[7],
			szHashData[8],szHashData[9],szHashData[10],szHashData[11],
			szHashData[12],szHashData[13],szHashData[14],szHashData[15]);
		return szHash;
	}
	return NULL;
} 

char* SHA1( const char* szSrc,char* szHash )
{
	BOOL bResult = TRUE;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD dwLength;
	BYTE szHashData[128];
	DWORD dwHashLen = 32;

	// Get handle to user default provider.
	if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0))
	{
		//如果密钥容器不存在,创建这个密钥容器[LCM 2012/11/21  16:41]
		if(GetLastError() == NTE_BAD_KEYSET)
		{
			if(!CryptAcquireContext(&hProv,	NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
				return NULL;
		}
		else
		{
			return NULL;
		}
	}

	// Create hash object.
	if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
	{
		// Hash password string.
		dwLength = strlen(szSrc);
		if (CryptHashData(hHash, (BYTE *)szSrc, dwLength, 0))
		{
			CryptGetHashParam(hHash,HP_HASHVAL,szHashData,&dwHashLen,0);
		}
		else
		{
			// Error during CryptHashData!
			bResult = FALSE;
		}
		CryptDestroyHash(hHash); // Destroy session key.
	}
	else
	{
		// Error during CryptCreateHash!
		bResult = FALSE;
	}
	CryptReleaseContext(hProv, 0);


	if (bResult)
	{
		sprintf(szHash, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			szHashData[0],szHashData[1],szHashData[2],szHashData[3],
			szHashData[4],szHashData[5],szHashData[6],szHashData[7],
			szHashData[8],szHashData[9],szHashData[10],szHashData[11],
			szHashData[12],szHashData[13],szHashData[14],szHashData[15],szHashData[16],szHashData[17],szHashData[18],
			szHashData[19]);
		return szHash;
	}
	return NULL;
}

