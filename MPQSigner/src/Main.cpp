/*
*	MPQSigner - Signs MPQ files with a Blizzard Weak Digital Signature
*	Copyright (C) 2014  xboi209 (xboi209@gmail.com)
*
*	This program is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*
*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License
*	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#if defined(_WIN32) && !defined(WIN32)
#define WIN32
#endif

#if _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define snprintf _snprintf
#endif

#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include "StormLib.h"


using namespace std;

int verifyArchive(HANDLE MPQ, char* args[]);

int main(int argc, char* args[])
{
	cout << "MPQSigner v1.0.0 - Sign MPQ files for a Blizzard Weak Digital Signature" << endl;
	cout << "by xboi209(xboi209@gmail.com) - 2014" << endl;
	cout << endl;

	if (argc != 2)
	{
		cout << "Invalid number of arguments(need 2, got " << argc << ")" << endl;
		return -1;
	}

	if (strcmp(args[1], "--help") == 0)
	{
		cout << "Usage: MPQSigner <filename>" << endl;
		return 0;
	}

	if (strcmp(args[1], "--about") == 0)
	{
		cout << "MPQSigner v1.0.0 by xboi209" << endl;
		cout << "StormLib v9.10 by Ladislav Zezula" << endl;
		cout << "Blizzard Weak Digital Signature private key by Tesseract2048(Tianyi HE)" << endl;
		return 0;
	}

	ifstream file(args[1]);
	if (file.is_open())
	{
		file.close();
	}
	else
	{
		cout << "Could not find file " << args[1] << endl;
		return -1;
	}


	//Ugly fix
	HANDLE tempMPQ = NULL;
	char newMPQname[256];
	char filename[MAX_PATH];
	char* output = strrchr(args[1], '.');

	if (output != NULL && strcmp(output, ".mpq") != 0) //file has an extension that isn't .mpq
	{
		//filename without extension
		char shortfilename[FILENAME_MAX];
		snprintf(shortfilename, 256, "%s", args[1]);
		memset(shortfilename + strlen(shortfilename) - strlen(output), '\0', 1);

		//filename with mpq extension
		snprintf(newMPQname, 256, "%s.mpq", shortfilename);

		if (SFileCreateArchive(newMPQname, MPQ_CREATE_ARCHIVE_V1 | MPQ_CREATE_ATTRIBUTES | MPQ_CREATE_SIGNATURE, HASH_TABLE_SIZE_DEFAULT, &tempMPQ) == true)
		{
			cout << "Created archive " << newMPQname << endl;
			if (SFileAddFileEx(tempMPQ, args[1], args[1], MPQ_FILE_COMPRESS | MPQ_FILE_SECTOR_CRC, MPQ_COMPRESSION_ZLIB, MPQ_COMPRESSION_NEXT_SAME) == true)
			{
				cout << "Added " << args[1] << " to archive " << newMPQname << endl;
			}
			else
			{
				cout << "Could not add " << args[1] << " to archive " << newMPQname << endl;
				SFileCloseArchive(tempMPQ);
				return -1;
			}
		}
		else
		{
			cout << "Could not create " << newMPQname << endl;
			return -1;
		}
		snprintf(filename, sizeof(filename), "%s", args[1]);
		args[1] = newMPQname;
	}
	else if (output == NULL) //file has no extension
	{
		snprintf(newMPQname, 256, "%s.mpq", args[1]);

		//copy and pasted because i'm too lazy
		if (SFileCreateArchive(newMPQname, MPQ_CREATE_ARCHIVE_V1 | MPQ_CREATE_ATTRIBUTES | MPQ_CREATE_SIGNATURE, HASH_TABLE_SIZE_DEFAULT, &tempMPQ) == true)
		{
			cout << "Created archive " << newMPQname << endl;
			if (SFileAddFileEx(tempMPQ, args[1], args[1], MPQ_FILE_COMPRESS | MPQ_FILE_SECTOR_CRC, MPQ_COMPRESSION_ZLIB, MPQ_COMPRESSION_NEXT_SAME) == true)
			{
				cout << "Added " << args[1] << " to archive " << newMPQname << endl;
			}
			else
			{
				cout << "Could not add " << args[1] << " to archive " << newMPQname << endl;
				SFileCloseArchive(tempMPQ);
				return -1;
			}
		}
		else
		{
			cout << "Could not create " << newMPQname << endl;
			return -1;
		}
		snprintf(filename, sizeof(filename), "%s", args[1]);
		args[1] = newMPQname;
		//end copy and paste
	}

	if (tempMPQ == NULL)
	{
		if (SFileOpenArchive((const TCHAR *)args[1], 0, STREAM_PROVIDER_FLAT | BASE_PROVIDER_FILE, &tempMPQ) == true)
		{
			cout << "Opened archive " << args[1] << endl;
		}
		else
		{
			cout << "Could not open " << args[1] << endl;
			return -1;
		}

		if (SFileSignArchive(tempMPQ, SIGNATURE_TYPE_WEAK) == true)
		{
			cout << "Signed archive " << args[1] << endl;
		}
		else
		{
			cout << "Could not sign archive " << args[1] << endl;
			return -1;
		}
	}

	if (SFileVerifyFile(tempMPQ, filename, SFILE_VERIFY_FILE_CRC) == VERIFY_FILE_HAS_CHECKSUM)
	{
		cout << "Verified CRC32 of file " << filename << endl;
	}
	else
	{
		cout << "WARNING: Could not verify CRC32 of file " << filename << endl;
	}

	if (SFileVerifyArchive(tempMPQ) == ERROR_WEAK_SIGNATURE_OK)
	{
		cout << args[1] << " contains a valid Blizzard Weak Digital Signature" << endl;
	}
	else
	{
		verifyArchive(tempMPQ, args);
		return -1;
	}

	if (SFileCompactArchive(tempMPQ, NULL, false) == true)
	{
		cout << "Compacted archive " << args[1] << endl;
	}
	else
	{
		cout << "WARNING: Could not compact archive " << args[1] << endl;
	}

	/* StormLib does not allow the removal of the listfile
	if (SFileRemoveFile(tempMPQ, LISTFILE_NAME, NULL) == true)
	{
		cout << "Removed listfile from archive " << args[1] << endl;
	}
	else
	{
		cout << "WARNING: Could not remove listfile from archive " << args[1] << endl;
	}
	*/

	if (SFileCloseArchive(tempMPQ))
	{
		cout << "Closed archive " << args[1] << endl;
	}
	else
	{
		cout << "Could not close archive " << args[1] << endl;
		return -1;
	}


	return 0;
}

int verifyArchive(HANDLE MPQ, char* args[])
{
	switch (SFileVerifyArchive(MPQ))
	{
	case ERROR_VERIFY_FAILED:
		cout << "Error during signature verification" << endl;
		break;
	case ERROR_WEAK_SIGNATURE_OK:
		cout << args[1] << " contains a Blizzard Weak Digital Signature" << endl;
		break;
	case ERROR_WEAK_SIGNATURE_ERROR:
		cout << "An invalid Blizzard Weak Digital Signature was found" << endl;
		break;
	case ERROR_STRONG_SIGNATURE_OK:
		cout << args[1] << " contains a Blizzard Strong Digital Signature" << endl;
		break;
	case ERROR_STRONG_SIGNATURE_ERROR:
		cout << "An invalid Blizzard Strong Digital Signature was found" << endl;
		break;
	default:
		cout << "An error has occurred" << endl;
		break;
	}

	return 0;
}