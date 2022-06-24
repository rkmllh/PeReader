#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <time.h>

#ifdef __GNUC__
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF     0x4000     // Image supports Control Flow Guard.
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020  // Image can handle a high entropy 64-bit virtual address space.
#endif // __GNUC__

#define INLINE      inline
#define STATIC      static
#define SIZEOF(el)  sizeof(el)
#define READONLY    const
#define PROCEDURE   void

#define OFFSET_YEAR(year)										\
	year += 0x0000076c

#define MEMCOPY(src, dest, size)								\
	memcpy(src,dest,size)

#define NTSIGNATURE(base)										\
	((LPVOID)((BYTE*)base + ((IMAGE_DOS_HEADER*)base)->e_lfanew))

#define IMAGEFILEHEADEROFFSET(base)								\
	(LPVOID)(((BYTE*)NTSIGNATURE(base)) + SIZEOF(DWORD))

#define IMAGEOPTIONALHEADEROFFSET(base)							\
	(LPVOID)((BYTE*)IMAGEFILEHEADEROFFSET(base) + SIZEOF(IMAGE_FILE_HEADER))

#define IMAGESECTIONHEADEROFFSET(base)							\
	(LPVOID)((BYTE*)IMAGEOPTIONALHEADEROFFSET(base) + SIZEOF(IMAGE_OPTIONAL_HEADER))

/*
*   IMAGE_IMPORT_DESCRIPTOR is Import Directory Table
*   for import sections, here it starts import informations.
*	It resolves references imported by DLL's.
*/
typedef IMAGE_IMPORT_DESCRIPTOR     IMPORT_DIRECTORY_TABLE;

INLINE PROCEDURE GetBaseAddress(VOID** base, READONLY CHAR* file);
PROCEDURE ImageDosHeader(READONLY IMAGE_DOS_HEADER* image_dos_header);
PROCEDURE ImageNtHeaders(READONLY IMAGE_NT_HEADERS* image_nt_header);
PROCEDURE ImageFileHeaders(READONLY IMAGE_FILE_HEADER* image_file_header);
PROCEDURE ImageOptionalHeaders(READONLY IMAGE_OPTIONAL_HEADER* image_optional_header);
PROCEDURE ImageSectionHeaders(READONLY IMAGE_SECTION_HEADER* image_section_header, WORD nSections);

/*Path to data directory*/
PROCEDURE ExportFunctions(READONLY LPVOID base, READONLY IMAGE_OPTIONAL_HEADER* image_optional_header);
PROCEDURE ImportFunctions(READONLY LPVOID base, READONLY IMAGE_OPTIONAL_HEADER* image_optional_header);

/*Print and die*/
STATIC INLINE PROCEDURE fatal(READONLY CHAR* what);

/*Free handle*/
STATIC INLINE PROCEDURE ReleaseResources(VOID);

STATIC HMODULE hLibrary = NULL;

INT main(INT argc, CHAR** argv)
{
	VOID* base = NULL;
	CHAR* image_name = NULL;

	IMAGE_DOS_HEADER* image_dos_header = NULL;
	IMAGE_NT_HEADERS* image_nt_headers = NULL;
	IMAGE_FILE_HEADER* image_file_header = NULL;
	IMAGE_OPTIONAL_HEADER* image_optional_header = NULL;
	IMAGE_SECTION_HEADER* image_section_header = NULL;

	if (argc > 1)
	{
		image_name = (CHAR*)GlobalAlloc(GPTR, (strlen(argv[1]) * SIZEOF(CHAR)) + SIZEOF(CHAR));

		if (image_name != NULL)
		{
			MEMCOPY(image_name, argv[1], strlen(argv[1]));
		}
		else
		{
			fatal("GlobalAlloc");
		}
	}
	else
	{
		printf("[!]No image specified. Loading information from current module..\n");
	}

	GetBaseAddress(&base, image_name);
	printf("\n\n[+]Base address(IMAGE_DOS_HEADER) at 0x%llx\n", (DWORD64)base);

	image_dos_header = (IMAGE_DOS_HEADER*)base;
	ImageDosHeader(image_dos_header);
	image_nt_headers = (IMAGE_NT_HEADERS*)NTSIGNATURE(base);
	printf("\n\n[+]IMAGE_NT_HEADERS at 0x%llx\n", (DWORD64)image_nt_headers);
	ImageNtHeaders(image_nt_headers);

	image_file_header = (IMAGE_FILE_HEADER*)IMAGEFILEHEADEROFFSET(base);
	printf("\n\n[+]IMAGE_FILE_HEADER at 0x%llx\n", (DWORD64)image_file_header);
	ImageFileHeaders(image_file_header);

	image_optional_header = (IMAGE_OPTIONAL_HEADER*)IMAGEOPTIONALHEADEROFFSET(base);
	printf("\n\n[+]IMAGE_OPTIONAL_HEADER at 0x%llx\n", (DWORD64)image_optional_header);
	ImageOptionalHeaders(image_optional_header);

	image_section_header = (IMAGE_SECTION_HEADER*)IMAGESECTIONHEADEROFFSET(base);
	printf("\n\n[+]IMAGE_SECTION_HEADER at 0x%llx\n", (DWORD64)image_section_header);
	ImageSectionHeaders(image_section_header, image_file_header->NumberOfSections);

	ExportFunctions(base, image_optional_header);
	ImportFunctions(base, image_optional_header);

	ReleaseResources();
	GlobalFree((HGLOBAL)image_name);
	ExitProcess(EXIT_SUCCESS);
}

PROCEDURE GetBaseAddress(VOID** base, READONLY CHAR* file)
{
	if (file && !(hLibrary = LoadLibrary(file)))
		fatal("LoadLibrary");
	if (!(*base = GetModuleHandle(file)))
		fatal("GetModuleHandle");
}

PROCEDURE ImageDosHeader(READONLY IMAGE_DOS_HEADER* image_dos_header)
{
	if (*(u_short*)&image_dos_header[0x00] == IMAGE_DOS_SIGNATURE)
		printf("[+]MS-DOS (IMAGE_DOS_SIGNATURE) compatible executable file\n");
	else
		fatal("Unknown format file!\n");

	printf("[+]Bytes on last page file: 0x%x\n", image_dos_header->e_cblp);
	printf("[+]Pages in file: 0x%x\n", image_dos_header->e_cp);
	printf("[+]Relocations: 0x%x\n", image_dos_header->e_crlc);
	printf("[+]Size of header: 0x%x\n", image_dos_header->e_cparhdr);
	printf("[+]Minimum paragraphs needed: 0x%x\n", image_dos_header->e_minalloc);
	printf("[+]Maximum paragraphs needed: 0x%x\n", image_dos_header->e_maxalloc);
	printf("[+]Initial stack segment value: 0x%x\n", image_dos_header->e_ss);
	printf("[+]Initial stack pointer value: 0x%x\n", image_dos_header->e_sp);
	printf("[+]Checksum: 0x%x\n", image_dos_header->e_csum);
	printf("[+]Initial instruction pointer value: 0x%x\n", image_dos_header->e_ip);
	printf("[+]Initial code segment value: 0x%x\n", image_dos_header->e_cs);
	printf("[+]Address relocation table: 0x%x\n", image_dos_header->e_lfarlc);
	printf("[+]Overlay number: 0x%x\n", image_dos_header->e_ovno);
	printf("[+]OEM identifier: 0x%x\n", image_dos_header->e_oemid);
	printf("[+]OEM information: 0x%x\n", image_dos_header->e_oeminfo);
	printf("[+]Offset of new header: 0x%x\n", image_dos_header->e_lfanew);

	return;
}

PROCEDURE ImageNtHeaders(READONLY IMAGE_NT_HEADERS* image_nt_header)
{
	printf("[+]Signature: ");

	switch (LOWORD(*(DWORD*)image_nt_header))
	{

	case IMAGE_OS2_SIGNATURE:
		printf("IMAGE_OS2_SIGNATURE");
		break;

	case IMAGE_OS2_SIGNATURE_LE:
		printf("IMAGE_OS2_SIGNATURE_LE");
		break;

	case IMAGE_NT_SIGNATURE:
		printf("IMAGE_NT_SIGNATURE");
		break;

	default:
		printf("IMAGE_DOS_SIGNATURE");
		break;
	}

	printf(" 0x%x\n", LOWORD(*(DWORD*)image_nt_header));

	return;
}

PROCEDURE ImageFileHeaders(READONLY IMAGE_FILE_HEADER* image_file_header)
{
	time_t linked_time = 0;
	struct tm* tm_linked_time = NULL;

	printf("[+]Architecture of image: ");

	switch (image_file_header->Machine)
	{
	case IMAGE_FILE_MACHINE_I386:
		printf("x86\n");
		break;

	case IMAGE_FILE_MACHINE_IA64:
		printf("Intel Itanium\n");
		break;

	case IMAGE_FILE_MACHINE_AMD64:
		printf("x64\n");
		break;

	default:
		printf("Unknown value (0x%x)\n", image_file_header->Machine);
		break;
	}

	printf("[+]Number of sections: 0x%x\n", image_file_header->NumberOfSections);

	linked_time = image_file_header->TimeDateStamp;
	tm_linked_time = gmtime(&linked_time);

	printf("[+]Linked data: %02d-%02d-%02d at %02d:%02d:%02d\n",
		OFFSET_YEAR(tm_linked_time->tm_year), tm_linked_time->tm_mon + 1, tm_linked_time->tm_mday,
		tm_linked_time->tm_hour + 1, tm_linked_time->tm_min, tm_linked_time->tm_sec
	);

	printf("[+]Pointer to symbol table: 0x%llx\n", (DWORD64)image_file_header->PointerToSymbolTable);
	printf("[+]Number of symbols: %d\n", image_file_header->NumberOfSymbols);
	printf("[+]Size of optional header: 0x%x\n", image_file_header->SizeOfOptionalHeader);
	printf("[+]Characteristics value: ");

	if (image_file_header->Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		printf("IMAGE_FILE_RELOCS_STRIPPED ");
	if (image_file_header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		printf("IMAGE_FILE_EXECUTABLE_IMAGE ");
	if (image_file_header->Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
		printf("IMAGE_FILE_LINE_NUMS_STRIPPED ");
	if (image_file_header->Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
		printf("IMAGE_FILE_LOCAL_SYMS_STRIPPED ");
	if (image_file_header->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
		printf("IMAGE_FILE_LARGE_ADDRESS_AWARE ");
	if (image_file_header->Characteristics & IMAGE_FILE_32BIT_MACHINE)
		printf("IMAGE_FILE_32BIT_MACHINE ");
	if (image_file_header->Characteristics & IMAGE_FILE_DEBUG_STRIPPED)
		printf("IMAGE_FILE_DEBUG_STRIPPED ");
	if (image_file_header->Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
		printf("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP ");
	if (image_file_header->Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
		printf("IMAGE_FILE_NET_RUN_FROM_SWAP ");
	if (image_file_header->Characteristics & IMAGE_FILE_SYSTEM)
		printf("IMAGE_FILE_SYSTEM ");
	if (image_file_header->Characteristics & IMAGE_FILE_DLL)
		printf("IMAGE_FILE_DLL ");
	if (image_file_header->Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
		printf("IMAGE_FILE_UP_SYSTEM_ONLY ");

	printf("(%#x)\n", image_file_header->Characteristics);

	return;
}

PROCEDURE ImageOptionalHeaders(READONLY IMAGE_OPTIONAL_HEADER* image_optional_header)
{
	printf("[+]State of image file: ");

	switch (image_optional_header->Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR_MAGIC:
		printf("executable image");
		break;
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		printf("ROM image");
		break;
	default:
		printf("Unknown image");
		break;
	}

	printf(" (0x%x)\n", image_optional_header->Magic);

	printf("[+]Major version number of linker: 0x%x\n", image_optional_header->MajorLinkerVersion);
	printf("[+]Minor version number of linker: 0x%x\n", image_optional_header->MinorLinkerVersion);
	printf("[+]Size of code: 0x%x\n", image_optional_header->SizeOfCode);
	printf("[+]Size of initialized data: 0x%x\n", image_optional_header->SizeOfInitializedData);
	printf("[+]Size of uninitialized data: 0x%x\n", image_optional_header->SizeOfUninitializedData);
	printf("[+]Entry point function (starting address for executables)(initalization function for drivers): 0x%x\n", image_optional_header->AddressOfEntryPoint);
	printf("[+]Base address of code: 0x%x\n", image_optional_header->BaseOfCode);

#ifndef _WIN64
	printf("[+]Base of image: 0x%x\n", image_optional_header->ImageBase);
#else
	printf("[+]Base of image: 0x%llx\n", image_optional_header->ImageBase);
#endif // !_WIN64

	printf("[+]Section alignment: 0x%x\n", image_optional_header->SectionAlignment);
	printf("[+]File alignment: 0x%x\n", image_optional_header->FileAlignment);
	printf("[+]Major OS version: 0x%x\n", image_optional_header->MajorOperatingSystemVersion);
	printf("[+]Minor OS version: 0x%x\n", image_optional_header->MinorOperatingSystemVersion);
	printf("[+]Major image version: 0x%x\n", image_optional_header->MajorImageVersion);
	printf("[+]Minor image version: 0x%x\n", image_optional_header->MinorImageVersion);
	printf("[+]Major subsystem version: 0x%x\n", image_optional_header->MajorSubsystemVersion);
	printf("[+]Minor subsystem version: 0x%x\n", image_optional_header->MinorSubsystemVersion);
	printf("[+]Size of image: 0x%x\n", image_optional_header->SizeOfImage);
	printf("[+]Size of headers: 0x%x\n", image_optional_header->SizeOfHeaders);
	printf("[+]Checksum: 0x%x\n", image_optional_header->CheckSum);
	printf("[+]Subsystem: ");

	switch (image_optional_header->Subsystem)
	{
	case IMAGE_SUBSYSTEM_UNKNOWN:
		printf("Unknown subsystem.\n");
		break;
	case IMAGE_SUBSYSTEM_NATIVE:
		printf("No subsystem required (device drivers and native system processes).\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		printf("Windows graphical user interface (GUI) subsystem.\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		printf("Windows character-mode user interface (CUI) subsystem.\n");
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		printf("OS/2 CUI subsystem.\n");
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		printf("POSIX CUI subsystem.\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		printf("Windows CE system.\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		printf("Extensible Firmware Interface (EFI) application.\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		printf("EFI driver with boot services.\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		printf("EFI driver with run-time services.\n");
		break;
	case IMAGE_SUBSYSTEM_EFI_ROM:
		printf("EFI ROM image.\n");
		break;
	case IMAGE_SUBSYSTEM_XBOX:
		printf("Xbox system.\n");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		printf("Boot application.\n");
		break;
	default:
		printf("0x%x\n", image_optional_header->Subsystem);
		break;
	}

	printf("[+]Dll characteristics: ");

	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
		printf("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		printf("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
		printf("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		printf("IMAGE_DLLCHARACTERISTICS_NX_COMPAT ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
		printf("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
		printf("IMAGE_DLLCHARACTERISTICS_NO_SEH ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND)
		printf("IMAGE_DLLCHARACTERISTICS_NO_BIND ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
		printf("IMAGE_DLLCHARACTERISTICS_APPCONTAINER ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
		printf("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
		printf("IMAGE_DLLCHARACTERISTICS_GUARD_CF ");
	if (image_optional_header->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
		printf("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ");

	printf("(%#x)\n", image_optional_header->DllCharacteristics);

#ifndef _WIN64
	printf("[+]Size of stack reserved: 0x%lx\n", image_optional_header->SizeOfStackReserve);
	printf("[+]Size of stack commit: 0x%lx\n", image_optional_header->SizeOfStackCommit);
	printf("[+]Size of heap reserved: 0x%lx\n", image_optional_header->SizeOfHeapReserve);
	printf("[+]Size of heap commit: 0x%lx\n", image_optional_header->SizeOfHeapCommit);
#else
	printf("[+]Size of stack reserved: 0x%llx\n", image_optional_header->SizeOfStackReserve);
	printf("[+]Size of stack commit: 0x%llx\n", image_optional_header->SizeOfStackCommit);
	printf("[+]Size of heap reserved: 0x%llx\n", image_optional_header->SizeOfHeapReserve);
	printf("[+]Size of heap commit: 0x%llx\n", image_optional_header->SizeOfHeapCommit);
#endif // !_WIN64

	printf("[+]Directory entries: 0x%x\n", image_optional_header->NumberOfRvaAndSizes);

#ifndef _WIN64
	printf("[+]IMAGE_DATA_DIRECTORY at 0x%x\n", (INT32)image_optional_header->DataDirectory);
#else
	printf("[+]IMAGE_DATA_DIRECTORY at 0x%llx\n", (INT64)image_optional_header->DataDirectory);
#endif // !_WIN64

	return;
}

PROCEDURE ImageSectionHeaders(READONLY IMAGE_SECTION_HEADER* image_section_header, WORD nSections)
{
	DWORD characteristics = 0;
	WORD i = 0;

	printf("[+]%19s%19s%19s%19s%19s\n", "Section", "Virtual", "SizeRawData", "PointerRawData", "Flag");

	for (i = 0; i < nSections; ++i, ++image_section_header)
	{
		characteristics = image_section_header->Characteristics;
		printf("[+]%19s%#19x%#19x%#19x",
			image_section_header->Name,
			image_section_header->VirtualAddress,
			image_section_header->SizeOfRawData,
			image_section_header->PointerToRawData
		);

		printf("%14s", "");

		if (characteristics & IMAGE_SCN_CNT_CODE)
			printf("code ");
		if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
			printf("init_data ");
		if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			printf("uninit_data ");
		if (characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			printf("not_cached ");
		if (characteristics & IMAGE_SCN_MEM_NOT_PAGED)
			printf("not_paged ");
		if (characteristics & IMAGE_SCN_MEM_SHARED)
			printf("shared ");
		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("exe ");
		if (characteristics & IMAGE_SCN_MEM_READ)
			printf("r ");
		if (characteristics & IMAGE_SCN_MEM_WRITE)
			printf("w ");

		printf("\n");
	}

	return;
}

PROCEDURE ExportFunctions(READONLY LPVOID base, READONLY IMAGE_OPTIONAL_HEADER* image_optional_header)
{
	time_t export_time = 0;
	struct tm* tm_export_time = NULL;
	IMAGE_DATA_DIRECTORY* image_data_directory = (IMAGE_DATA_DIRECTORY*)image_optional_header->DataDirectory;
	IMAGE_EXPORT_DIRECTORY* image_export_directory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)base + image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PULONG export_address_table_RVA = NULL;
	PULONG name_pointer_RVA = NULL;
	PUSHORT ordinal_table_RVA = NULL;

	DWORD i = 0;

	/*Check number of directories*/
	if (IMAGE_DIRECTORY_ENTRY_EXPORT < image_optional_header->NumberOfRvaAndSizes)
	{
		printf("\n  IMAGE_DIRECTORY_ENTRY_EXPORT\tSize\tVirtualAddress \n"
			"  ----------------------------\t----\t--------------\n"
			"                              \t%#x \t%#x           \n\n",
			image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
			image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
		);

		/*Check size of segment*/
		if (image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			image_data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			export_address_table_RVA = (PULONG)((BYTE*)base + image_export_directory->AddressOfFunctions);
			name_pointer_RVA = (PULONG)((BYTE*)base + image_export_directory->AddressOfNames);
			ordinal_table_RVA = (PUSHORT)((BYTE*)base + image_export_directory->AddressOfNameOrdinals);

			printf("[+]IMAGE_EXPORT_DIRECTORY at 0x%p\n", image_export_directory);
			printf("[+]Major version: %d\n", image_export_directory->MajorVersion);
			printf("[+]Minor version: %d\n", image_export_directory->MinorVersion);
			printf("[+]Name of image: %s\n", (BYTE*)base + image_export_directory->Name);
			printf("[+]Base (starting ordinal index for export address table): %d\n", image_export_directory->Base);
			printf("[+]Number of functions: %d\n", image_export_directory->NumberOfFunctions);
			printf("[+]Number of names: %d\n", image_export_directory->NumberOfNames);

			export_time = image_export_directory->TimeDateStamp;
			tm_export_time = gmtime(&export_time);
			printf("[+]Creation data: %02d-%02d-%02d at %02d:%02d:%02d\n",
				OFFSET_YEAR(tm_export_time->tm_year), tm_export_time->tm_mon + 1, tm_export_time->tm_mday,
				tm_export_time->tm_hour + 1, tm_export_time->tm_min, tm_export_time->tm_sec
			);

			printf("Ordinal%10sAddress%10sName  \n%s%17s%17s", "", "",
				"-------",
				"-------",
				"----\n"
			);

			for (i = 0; i < image_export_directory->NumberOfNames; ++i)
			{
#ifndef _WIN64
				fprintf(stdout, "%d%10s%#x%10s%s\n",
					(USHORT)ordinal_table_RVA[i],
					"",
					(INT32)((BYTE*)base + export_address_table_RVA[ordinal_table_RVA[i]]),
					"",
					((BYTE*)base + name_pointer_RVA[i])
				);
#else
				fprintf(stdout, "%d%10s%#llx%10s%s\n",
					(USHORT)ordinal_table_RVA[i],
					"",
					(INT64)((BYTE*)base + export_address_table_RVA[ordinal_table_RVA[i]]),
					"",
					((BYTE*)base + name_pointer_RVA[i])
				);
#endif // !_WIN64
			}
		}
	}

	return;
}

PROCEDURE ImportFunctions(READONLY LPVOID base, READONLY IMAGE_OPTIONAL_HEADER* image_optional_header)
{
	time_t import_time = 0;
	struct tm* tm_import_time = NULL;

	READONLY BYTE* dll_name = NULL;

	IMAGE_DATA_DIRECTORY* image_data_directory = (IMAGE_DATA_DIRECTORY*)image_optional_header->DataDirectory;
	IMPORT_DIRECTORY_TABLE* import_directory_table = (IMPORT_DIRECTORY_TABLE*)((BYTE*)base + image_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	IMAGE_THUNK_DATA* original_first_thunk_data = NULL;
	IMAGE_THUNK_DATA* first_thunk_data = NULL;

	IMAGE_IMPORT_BY_NAME* procedure = NULL;

	READONLY CHAR* proc_name = NULL;

	ULONGLONG proc_address = 0;

	/*
	*   Now import_directory_table points to array of import directory entries.
	*   Each directory entries describes a DLL.
	*/

	/*Check number of directories*/
	if (IMAGE_DIRECTORY_ENTRY_IMPORT < image_optional_header->NumberOfRvaAndSizes)
	{
		printf("\n  IMAGE_DIRECTORY_ENTRY_IMPORT\tSize\tVirtualAddress \n"
			"  ----------------------------\t----\t--------------\n"
			"                              \t%#x \t%#x           \n\n",
			image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
			image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
		);

		if (image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress &&
			image_data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			while (import_directory_table->OriginalFirstThunk)
			{
				/*Retrieve time*/
				import_time = import_directory_table->TimeDateStamp;
				tm_import_time = gmtime(&import_time);
				printf("[+]Creation data: %02d-%02d-%02d at %02d:%02d:%02d\n",
					OFFSET_YEAR(tm_import_time->tm_year), tm_import_time->tm_mon + 1, tm_import_time->tm_mday,
					tm_import_time->tm_hour + 1, tm_import_time->tm_min, tm_import_time->tm_sec
				);

				dll_name = (BYTE*)base + import_directory_table->Name;

				printf("%#x %s %#x\n", import_directory_table->OriginalFirstThunk, dll_name, import_directory_table->FirstThunk);

				original_first_thunk_data = (IMAGE_THUNK_DATA*)((DWORD_PTR)base + import_directory_table->OriginalFirstThunk);
				first_thunk_data = (IMAGE_THUNK_DATA*)((DWORD_PTR)base + import_directory_table->FirstThunk);

				while (!(original_first_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					&& original_first_thunk_data->u1.AddressOfData)
				{
					//Find procedure in dll
					procedure = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)base + original_first_thunk_data->u1.AddressOfData);

					proc_name = procedure->Name;
					proc_address = first_thunk_data->u1.Function;

					printf("     %#llx %s\n", proc_address, proc_name);

					original_first_thunk_data++;
					first_thunk_data++;
				}

				printf("\n");
				++import_directory_table;
			}
		}
	}

	return;
}

STATIC INLINE PROCEDURE fatal(READONLY CHAR* what)
{
	CHAR* errmsg = NULL;
	CHAR errbuf[MAX_PATH];
	SecureZeroMemory(errbuf, MAX_PATH);

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(char*)&errmsg,
		0,
		NULL
	);

	snprintf(errbuf, MAX_PATH, "[-]Error in %s. Program terminated! Last error was (%d) - %s\n", what, GetLastError(), errmsg);
	printf(errbuf);

	LocalFree((errmsg));
	ExitProcess(EXIT_FAILURE);
}

STATIC INLINE PROCEDURE ReleaseResources(VOID)
{
	if (hLibrary != NULL)
	{
		FreeLibrary(hLibrary);
		hLibrary = NULL;
	}
}