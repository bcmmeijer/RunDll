#include <Windows.h>
#include <stdexcept>
#include <tuple>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#ifdef _WIN64
#define ARCH_SIG IMAGE_FILE_MACHINE_AMD64
#else
#define ARCH_SIG IMAGE_FILE_MACHINE_I386
#endif

bool verify_arch(const std::wstring& path) {
	constexpr size_t	size = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS);
	uint8_t				buffer[size] = { 0 };
	HANDLE				file = nullptr;
	DWORD				read = 0;
	PIMAGE_DOS_HEADER	dos = nullptr;
	PIMAGE_NT_HEADERS	nt = nullptr;

	file = CreateFileW(path.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!file || file == INVALID_HANDLE_VALUE) throw std::runtime_error("[-] Could not open specified DLL");

	if (!ReadFile(file, buffer, size, &read, nullptr)) {
		CloseHandle(file);
		throw std::runtime_error("[-] Could not read file");
	}

	CloseHandle(file);

	dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("[-] DOS header signature does not match expected signature");

	nt = reinterpret_cast<PIMAGE_NT_HEADERS>((uintptr_t)dos + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("[-] NT headers signature does not match expected signature");

	return nt->FileHeader.Machine == ARCH_SIG;
}

FARPROC get_proc_addr(HMODULE base, const std::wstring& function, bool name_mangling = false) {

	int						size_needed;
	char*					buffer;
	PDWORD					Address, Name;
	PWORD					Ordinal;
	PIMAGE_DOS_HEADER		dos;
	PIMAGE_NT_HEADERS		nt;
	PIMAGE_EXPORT_DIRECTORY exports;

	if (function.empty()) return nullptr;
	size_needed = WideCharToMultiByte(CP_UTF8, 0, function.c_str(), function.size(), nullptr, 0, nullptr, nullptr);
	
	buffer = new char[size_needed + 1];
	memset(buffer, 0, function.length());
	
	if (!WideCharToMultiByte(CP_UTF8, 0, function.c_str(), function.size(), buffer, size_needed, nullptr, nullptr)) {
		delete[] buffer;
		throw std::runtime_error("[-] Could not convert ANSI to ASCII");
	}

	buffer[size_needed] = '\0';
	std::string name = buffer;
	delete[] buffer;

	dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	nt = reinterpret_cast<PIMAGE_NT_HEADERS>((uintptr_t)base + dos->e_lfanew);

	if (!nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		throw std::runtime_error("[-] IMAGE_DIRECTORY_ENTRY_EXPORT not found");

	exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((uint8_t*)dos + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	Address = reinterpret_cast<PDWORD>((uint8_t*)dos + exports->AddressOfFunctions);
	Name	= reinterpret_cast<PDWORD>((uint8_t*)dos + exports->AddressOfNames);
	Ordinal = reinterpret_cast<PWORD>((uint8_t*)dos + exports->AddressOfNameOrdinals);

	for (size_t i = 0; i < exports->NumberOfNames; i++) {
		const char* _n = (const char*)dos + Name[i];
		FARPROC proc = reinterpret_cast<FARPROC>((uint8_t*)dos + Address[Ordinal[i]]);

		if (name_mangling) {
			if (strstr(_n, name.c_str())) return proc;
		}
		else {
			if (!strcmp(_n, name.c_str()))
				return proc;
		}
	}

	return nullptr;
}

int wmain(int argc, wchar_t** argv) {

	int					is_func_specified = 0;
	HMODULE				loaded_dll = nullptr;
	FARPROC				func = nullptr;
	std::wstring		full_path, path, function;

	try {

		if (!argc || argc < 2) 
			throw std::runtime_error("[!] Please specify dll to load");

		full_path = argv[1];

		is_func_specified = full_path.find(':');
		if (is_func_specified != std::wstring::npos) {
			path = full_path.substr(0, is_func_specified);
			function = full_path.substr(is_func_specified + 1, full_path.length());

			wprintf(L"[*] DLL: %s\n", path.c_str());
			wprintf(L"[*] FUNC: %s\n", function.c_str());
		}
		else {
			path = full_path;
			wprintf(L"[*] DLL: %s\n", path.c_str());
			wprintf(L"[*] No function specified. Only calling DllMain\n");
		}

		if (!verify_arch(path)) 
			throw std::runtime_error("[-] Architecture of dll does not match loader. maybe use the other loader?!");

		loaded_dll = LoadLibraryW(path.c_str());
		if (!loaded_dll) throw std::runtime_error("[-] Failed to load specified DLL");

		wprintf(L"[*] DLL Loaded\n");

		if (is_func_specified != std::wstring::npos) {

			wprintf(L"[!] Function calling is in beta!! Signature for function calls is void*(*)(void*)\n");

			func = get_proc_addr(loaded_dll, function);
			if (!func) {
				wprintf(L"[!] Could not find function in export table. Retrying with name mangling...\n");
				func = get_proc_addr(loaded_dll, function, true);
			}
			if (!func) throw std::runtime_error("[-] Could not find specified function in export table");

			if (argc >= 3) 
				wprintf(L"[*] Function %s: %p\n", function.c_str(), reinterpret_cast<void*(*)(void*)>(func)(argv[2]));
			else 
				wprintf(L"[*] Function %s: %p\n", function.c_str(), reinterpret_cast<void* (*)(void*)>(func)(nullptr));

		}
	}
	catch (const std::runtime_error & e) {
		printf("[-] %s: GetLastError=%d\n", e.what(), GetLastError());
	}

	return 0;
}