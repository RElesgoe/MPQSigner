/*
*	MPQSigner - Signs MPQ files with a Blizzard Weak Digital Signature
*	Copyright (C) 2014-2015  xboi209 (xboi209@gmail.com)
*
*	Permission to use, copy, modify, and/or distribute this software for any purpose with or without
*	fee is hereby granted, provided that the above copyright notice and this permission notice appear
*	in all copies.
*
*	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
*	SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
*	AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
*	OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#define MPQSIGNER_VERSION u8"1.2.0"

#include <cstdlib>
#include <cstring>
#include <filesystem> //Currently non-standard, https://msdn.microsoft.com/en-us/library/hh874694.aspx
#include <iostream>
#include <string>
#include "StormLib.h"

namespace filesystem = std::tr2::sys;

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cerr << u8"Invalid number of arguments(need 2, got " << argc << u8")" << std::endl;
		return EXIT_FAILURE;
	}

	filesystem::path p(argv[1]);

	if (p.string() == "--help" || p.string() == "--usage" || p.string() == "-h" || p.string() == "-?")
	{
		std::cout << u8"usage: mpqsigner [<options>] [<filename>]" << std::endl;
		std::cout << u8"\t--help, --usage, -h, -?\tdisplay this information and exit" << std::endl;
		std::cout << u8"\t--version, -v,\tdisplay version number and exit" << std::endl;
		return EXIT_SUCCESS;
	}

	if (p.string() == "--version" || p.string() == "-v")
	{
		std::cout << u8"MPQSigner v" << MPQSIGNER_VERSION << u8" Copyright (c) 2014-2015 xboi209(xboi209@gmail.com)" << std::endl;
		std::cout << u8"StormLib v" << STORMLIB_VERSION_STRING << u8" Copyright (c) 1999-2013 Ladislav Zezula" << std::endl;
		return EXIT_SUCCESS;
	}

	if (!filesystem::exists(p))
	{
		std::cerr << p.string() << u8" does not exist" << std::endl;
		return EXIT_FAILURE;
	}

	if (!filesystem::is_regular_file(p))
	{
		std::cerr << p.string() << u8" is not a regular file" << std::endl;
		return EXIT_FAILURE;
	}

	SFILE_CREATE_MPQ mpqinfo;
	std::memset(&mpqinfo, 0, sizeof(SFILE_CREATE_MPQ));
	mpqinfo.cbSize = sizeof(SFILE_CREATE_MPQ);
	mpqinfo.dwMpqVersion = MPQ_FORMAT_VERSION_1; /* Version 1.0 */
	mpqinfo.dwStreamFlags = STREAM_PROVIDER_FLAT | BASE_PROVIDER_FILE;
	mpqinfo.dwFileFlags1 = 1; /* Use (listfile) */
	mpqinfo.dwFileFlags2 = 1; /* Use (attributes) file */
	mpqinfo.dwFileFlags3 = MPQ_FILE_EXISTS; /* Use (signature) file */
	mpqinfo.dwAttrFlags = MPQ_ATTRIBUTE_CRC32 | MPQ_ATTRIBUTE_FILETIME | MPQ_ATTRIBUTE_MD5;
	mpqinfo.dwSectorSize = 0x1000;
	mpqinfo.dwRawChunkSize = 0; // Used only if MPQ v4
	mpqinfo.dwMaxFileCount = HASH_TABLE_SIZE_MIN;
	HANDLE hArchive;
	std::string mpqname = p.stem().string() + ".mpq"; // Filename with .mpq extension

	if (p.has_extension())
	{
		if (p.extension() != ".mpq")
		{
			if (SFileCreateArchive2(mpqname.c_str(), &mpqinfo, &hArchive))
			{
				std::cout << u8"Created archive " << mpqname << std::endl;
			}
			else
			{
				std::cerr << u8"Could not create archive " << mpqname << std::endl;
				return EXIT_FAILURE;
			}
		}
		else // File has .mpq extension, just open and sign it
		{
			SFileOpenArchive(p.string().c_str(), 0/* unused */, STREAM_PROVIDER_FLAT | BASE_PROVIDER_FILE, &hArchive);
			goto signArchive;
		}
	}
	else // File with no extension
	{
		if (SFileCreateArchive2(mpqname.c_str(), &mpqinfo, &hArchive))
		{
			std::cout << u8"Created archive " << mpqname << std::endl;
		}
		else
		{
			std::cerr << u8"Could not create archive " << mpqname << std::endl;
			return EXIT_FAILURE;
		}
	}

	if (SFileAddFileEx(hArchive, p.string().c_str(), p.filename().string().c_str(), MPQ_FILE_COMPRESS | MPQ_FILE_SECTOR_CRC, MPQ_COMPRESSION_PKWARE, MPQ_COMPRESSION_NEXT_SAME))
	{
		std::cout << u8"Added file " << p.string() << u8" to archive" << std::endl;

		// informational, can be removed
		HANDLE hFile = nullptr;
		if (SFileOpenFileEx(hArchive, p.string().c_str(), SFILE_OPEN_FROM_MPQ, &hFile))
		{
			DWORD szFilehigh = 0;
			DWORD szFilelow = 0;
			szFilelow = SFileGetFileSize(hFile, &szFilehigh);
			if (szFilelow != SFILE_INVALID_SIZE)
			{
				std::cout << u8"File size(low): " << szFilelow << std::endl;
				std::cout << u8"File size(high): " << szFilehigh << std::endl;
			}
		}
	}
	else
	{
		std::cerr << u8"Could not add file " << p.string() << u8" to archive" << std::endl;
		SFileCloseArchive(hArchive);
		return EXIT_FAILURE;
	}

	/*
	*	http://www.zezula.net/en/mpq/stormlib/sfileverifyfile.html
	*	Documentation is unclear to me...
	*/
	switch (SFileVerifyFile(hArchive, p.filename().string().c_str(), SFILE_VERIFY_FILE_CRC))
	{
	case 0:
		std::cout << u8"File verified" << std::endl;
		break;
	case VERIFY_OPEN_ERROR:
		std::cerr << u8"Could not open file " << p.string() << std::endl;
		break;
	case VERIFY_READ_ERROR:
		std::cerr << u8"Could not read file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_HAS_CHECKSUM:
		std::cout << u8"Verified CRC32 of file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_CHECKSUM_ERROR:
		std::cout << u8"Verification of CRC32 of file " << p.string() << u8" failed" << std::endl;
		break;
	default:
		std::cerr << u8"An error has occurred" << std::endl;
		break;
	}
	switch (SFileVerifyFile(hArchive, p.filename().string().c_str(), SFILE_VERIFY_FILE_MD5))
	{
	case 0:
		std::cout << u8"File verified" << std::endl;
		break;
	case VERIFY_OPEN_ERROR:
		std::cerr << u8"Could not open file " << p.string() << std::endl;
		break;
	case VERIFY_READ_ERROR:
		std::cerr << u8"Could not read file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_HAS_MD5:
		std::cout << u8"Verified MD5 of file " << p.string() << std::endl;
		break;
	case VERIFY_FILE_MD5_ERROR:
		std::cout << u8"Verification of MD5 of file " << p.string() << u8" failed" << std::endl;
		break;
	default:
		std::cerr << u8"An error has occurred" << std::endl;
		break;
	}


signArchive:
	switch (SFileVerifyArchive(hArchive))
	{
	case ERROR_NO_SIGNATURE:
		if (SFileSignArchive(hArchive, SIGNATURE_TYPE_WEAK))
		{
			std::cout << u8"Signed archive" << std::endl;
			std::cout << u8"Signature: Blizzard Weak Digital Signature" << std::endl;
		}
		else
		{
			std::cerr << u8"Could not sign archive" << std::endl;
			SFileCloseArchive(hArchive);
			return EXIT_FAILURE;
		}
		break;
	case ERROR_VERIFY_FAILED:
		std::cerr << u8"An error has occured during signature verification" << std::endl;
		SFileCloseArchive(hArchive);
		return EXIT_FAILURE;
	case ERROR_WEAK_SIGNATURE_OK:
		std::cout << u8"Signed archive" << std::endl;
		std::cout << u8"Signature: Blizzard Weak Digital Signature" << std::endl;
		break;
	case ERROR_WEAK_SIGNATURE_ERROR:
		std::cerr << u8"An invalid Blizzard Weak Digital Signature was found" << std::endl;
		SFileCloseArchive(hArchive);
		return EXIT_FAILURE;
	case ERROR_STRONG_SIGNATURE_OK:
		std::cout << u8"Signature: Blizzard Strong Digital Signature" << std::endl;
		break;
	case ERROR_STRONG_SIGNATURE_ERROR:
		std::cerr << u8"An invalid Blizzard Strong Digital Signature was found" << std::endl;
		SFileCloseArchive(hArchive);
		return EXIT_FAILURE;
	default:
		std::cerr << u8"An error has occurred" << std::endl;
		SFileCloseArchive(hArchive);
		return EXIT_FAILURE;
	}


	if (SFileCompactArchive(hArchive, NULL, false) != 0)
	{
		std::cout << u8"Compacted archive" << std::endl;
	}
	else
	{
		std::cerr << u8"Could not compact archive" << std::endl;
	}

	if (SFileCloseArchive(hArchive))
	{
		std::cout << u8"Closed archive" << std::endl;
	}
	else
	{
		std::cerr << u8"Could not close archive" << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}