/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <iostream>
#include <fstream>
#include <string>

#define  USE_WIN_CRYPT

#ifdef USE_WIN_CRYPT
#include "crypt.h"
#else
#include <botan/botan.h>
#endif


int main(int argc, char* argv[])
{

#ifdef USE_WIN_CRYPT
	if(argc != 2)
	{
		std::cout << "Usage: " << argv[0] << " ×Ö·û´®" << std::endl;
		return 1;
	}
	std::string hash = argv[1];

	char szMD5Ret[128]={0};
	if(!MD5(hash.c_str(),szMD5Ret))
		std::cout<<"md5 ¼ÆËãÊ§°Ü"<<std::endl;
	else
		std::cout<<szMD5Ret<<std::endl;

	char szSHA1[128]={0};
	if (!SHA1(hash.c_str(),szSHA1))
		std::cout<<"sha1 ¼ÆËãÊ§°Ü"<<std::endl;
	else
		std::cout<<szSHA1<<std::endl;
	

#else

	if(argc < 3)
	{
		std::cout << "Usage: " << argv[0] << " digest <filenames>" << std::endl;
		return 1;
	}	

	std::string hash = argv[1];
	/* a couple of special cases, kind of a crock */
	if(hash == "sha1") hash = "SHA-1";
	if(hash == "md5")  hash = "MD5";

	try {
		Botan::LibraryInitializer init;
		if(!Botan::have_hash(hash))
		{
			std::cout << "Unknown hash \"" << argv[1] << "\"" << std::endl;
			return 1;
		}

		Botan::Pipe pipe(new Botan::Hash_Filter(hash),
			new Botan::Hex_Encoder);

		int skipped = 0;
		for(int j = 2; argv[j] != 0; j++)
		{
			std::ifstream file(argv[j], std::ios::binary);
			if(!file)
			{
				std::cout << "ERROR: could not open " << argv[j] << std::endl;
				skipped++;
				continue;
			}
			pipe.start_msg();
			file >> pipe;
			pipe.end_msg();
			pipe.set_default_msg(j-2-skipped);
			std::cout << pipe << "  " << argv[j] << std::endl;
		}
	}
	catch(std::exception& e)
	{
		std::cout << "Exception caught: " << e.what() << std::endl;
	}
#endif
	system("pause");
	return 0;
}
