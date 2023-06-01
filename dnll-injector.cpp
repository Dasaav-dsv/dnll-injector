#include "dnll-injector.h"

// Undo default Microsoft UNICODE defines that override base function names.
#undef Process32First
#undef Process32Next
#undef PROCESSENTRY32

static inline char is32Bit = -1;
static std::string workDir;

void logHelp(Logger& logger) {;
	logger.log("Usage:\nUse with an executable file to set it as the injection target.\nAny subsequent dlls passed as arguments will be injected into the running process,\nor a process will be created with these dlls loaded first.");
}

DWORD getCharacteristics(std::ifstream& file) {
	auto DOS = std::make_unique<IMAGE_DOS_HEADER>();
	file.read(reinterpret_cast<char*>(DOS.get()), sizeof(IMAGE_DOS_HEADER));
	file.seekg(DOS->e_lfanew);
	auto headers = std::make_unique<IMAGE_NT_HEADERS>();
	file.read(reinterpret_cast<char*>(headers.get()), sizeof(IMAGE_NT_HEADERS));
	return headers->FileHeader.Characteristics;
}

bool processFile(const std::string& path, std::string& exe, std::vector<std::string>& dlls, Logger& logger) {
	std::ifstream file(path, std::ios::binary);
	DWORD characteristics = getCharacteristics(file);
	bool bitness32 = (characteristics >> 8) & 1;
	if (is32Bit < 0) is32Bit = bitness32;
	else if (is32Bit != bitness32) {
		logger.log("The bitness of %s does not match the rest of the input files, %d-bit expected, got %d-bit", path.c_str(), is32Bit ? 32 : 64, bitness32 ? 32 : 64);
		return false;
	}
	if ((characteristics >> 13) & 1) {
		dlls.push_back(path);
		return true;
	}
	else if (((characteristics >> 1) & 1)) {
		if (exe.empty()) {
			exe = path;
			return true;
		}
		else {
			logger.log("Error: multiple executables provided to injector");
			return false;
		}
	}
	else {
		logger.log("Error: unknown file format - is neither executable nor a dll");
		return false;
	}
}

bool processFile(const std::string& path, std::string& exe, Logger& logger) {
	std::vector<std::string> dlls{};
	return processFile(path, exe, dlls, logger);
}

bool processArg(std::string arg, std::string& exe, std::vector<std::string>& dlls, Logger& logger) {
	if (arg == "-h" || arg == "-help") {
		logHelp(logger);
		return true;
	}
	std::filesystem::path path{ arg };
	if (std::filesystem::is_directory(path)) {
		for (const auto& file : std::filesystem::directory_iterator(path)) {
			if (file.path().extension() == ".dll") {
				if (!processArg(file.path().generic_string(), exe, dlls, logger)) return false;
			}
		}
	}
	else {
		auto ext = path.extension().string();
		if (ext != ".exe" && ext != ".dll") {
			logger.log("Error: unrecognized file extension \"%s\"", ext.c_str());
			return false;
		}
		return processFile(arg, exe, dlls, logger);
	}
}

bool targetExe(std::string& exe, Logger& logger) {
	if (exe.empty()) {
		std::ifstream file(workDir + "/dnll-injector-target.txt");
		if (!file) {
			logger.log("Error: no executable file was provided as an argument or set as the injector's target");
			return false;
		}
		std::string exePath;
		std::getline(file, exePath);
		return processFile(exePath, exe, logger);
	}
	else {
		std::ofstream file(workDir + "/dnll-injector-target.txt");
		if (!file) {
			logger.log("Warning: unable to create injector target file");
			return true;
		}
		file << exe;
		logger.log("Saved injector target with path %s", exe.c_str());
		return true;
	}
}

std::vector<char*> makeDllArray(std::vector<std::string>& dlls) {
	auto& logger = Logger::get();
	int count = 1;
	std::vector<char*> rlpDlls{};
	for (auto& path : dlls) {
		logger.log("%d: %s", count++, path.c_str());
		rlpDlls.push_back(path.data());
	}
	return rlpDlls;
}

bool injectDlls(const std::string& exe, DWORD pid, const std::vector<std::string>& dlls) {
	auto& logger = Logger::get();
	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (pHandle == INVALID_HANDLE_VALUE) {
		logger.log("Error: unable to open process %s, OpenProcess returned 0x%08X", exe.c_str(), GetLastError());
		return false;
	}
	HMODULE k32Handle = GetModuleHandleA("Kernel32.dll");
	if (!k32Handle) {
		logger.log("Error: unable to get Kernel32.dll handle. This should not ever happen, and the check is here to pacify the compiler. If you get this error, good luck.");
		CloseHandle(pHandle);
		return false;
	}
	if (FARPROC procLLA = GetProcAddress(k32Handle, "LoadLibraryA")) {
		int count = 1;
		for (auto& dll : dlls) {
			std::size_t allocSize = dll.length() * sizeof(dll.front()) + 1;
			if (void* alloc = VirtualAllocEx(pHandle, NULL, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
				logger.log("%d: %s", count++, dll.c_str());
				if (!WriteProcessMemory(pHandle, alloc, dll.c_str(), allocSize, NULL)) {
					logger.log("Error: unable to write memory inside process %s, WriteProcessMemory returned 0x%08X", exe.c_str(), GetLastError());
					CloseHandle(pHandle);
					return false;
				}
				HANDLE loadThread = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)procLLA, alloc, 0, NULL);
				if (!loadThread) {
					logger.log("Error: unable to create thread inside process %s, CreateRemoteThread returned 0x%08X", exe.c_str(), GetLastError());
					CloseHandle(pHandle);
					return false;
				}
				WaitForSingleObject(loadThread, INFINITE);
				VirtualFreeEx(pHandle, alloc, 0, MEM_RELEASE);
				CloseHandle(loadThread);
			}
			else {
				logger.log("Error: unable to allocate memory inside process %s, VirtualAllocEx returned 0x%08X", exe.c_str(), GetLastError());
				return false;
			}
		}
		logger.log("Successfully injected %d dll%s into process %s", dlls.size(), dlls.size() > 1 ? "s" : "", exe.c_str());
		CloseHandle(pHandle);
		return true;
	}
	else {
		logger.log("Error: unable to get LoadLibraryA FARPROC, GetProcAddress returned 0x%08X", GetLastError());
		CloseHandle(pHandle);
		return false;
	}
}

int main(int argc, char* argv[]) {
	auto& logger = Logger::get();
	if (argc <= 1) {
		logger.log("Error: dnll-injector requires at least one argument");
		logHelp(logger);
		system("PAUSE");
		return 0;
	}
	workDir = std::filesystem::path(argv[0]).parent_path().generic_string();
	std::string exe{};
	std::vector<std::string> dlls{};
	for (int i = 1; i < argc; ++i) {
		if (!processArg(argv[i], exe, dlls, logger)) {
			logger.log("Encountered an error while processing arguments, terminating...");
			system("PAUSE");
			return 0;
		}
	}
	if (!targetExe(exe, logger)) {
		system("PAUSE");
		return 0;
	}
	if (!dlls.size()) {
		return 0;
	}
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		logger.log("Error: unable to create a process snapshot, CreateToolhelp32Snapshot returned 0x%08X", GetLastError());
		system("PAUSE");
		return 0;
	}
	PROCESSENTRY32 pe32{};
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnap, &pe32)) {
		CloseHandle(hSnap);
		logger.log("Error: Module32First returned 0x%08X", GetLastError());
		system("PAUSE");
		return 0;
	}
	std::vector<DWORD> pids{};
	std::string exeName = std::filesystem::path{ exe }.filename().generic_string();
	do { if (exeName == pe32.szExeFile) pids.push_back(pe32.th32ProcessID); } while (Process32Next(hSnap, &pe32));
	CloseHandle(hSnap);
	if (pids.size() == 1) {
		logger.log("Target process %s; injecting dlls:", exe.c_str());
		if (!injectDlls(exe, pids[0], dlls)) {
			logger.log("Encountered an error while injecting dlls, terminating...");
		}
		system("PAUSE");
		return 0;
	}
	else if (pids.size() > 1) {
		std::string in{};
		do {
			int pid = -1;
			if (in.length()) pid = std::stoi(in);
			if (std::find(pids.begin(), pids.end(), pid) != pids.end()) {
				if (!injectDlls(exe, pid, dlls)) {
					logger.log("Encountered an error while injecting dlls, terminating...");
				}
				system("PAUSE");
				return 0;
			}
			std::cout << "Multiple executables with the same target name present, choose PID from:";
			for (auto pid : pids) {
				std::cout << "\n\"" << exeName << "\" " << pid;
			}
			std::cout << "\nInput PID: ";
		} while (std::getline(std::cin, in));
		logger.log("Error when receiving console input, terminating...");
		system("PAUSE");
		return 0;
	}
	else {
		logger.log("Creating process %s with dlls:", exe.c_str());
		auto rlpDlls = makeDllArray(dlls);
		PROCESS_INFORMATION pInfo;
		STARTUPINFOA sInfo{};
		sInfo.cb = sizeof(sInfo);
		sInfo.dwFlags = NULL;
		DWORD flags = CREATE_DEFAULT_ERROR_MODE | DETACHED_PROCESS | CREATE_SUSPENDED;
		if (!DetourCreateProcessWithDllsA(exe.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, std::filesystem::path(exe).parent_path().string().c_str(), &sInfo, &pInfo, rlpDlls.size(), (LPCSTR*)rlpDlls.data(), NULL)) {
			logger.log("Error: DetourCreateProcessWithDllsA called unsuccessfully, returned error code 0x%08X", GetLastError());
			system("PAUSE");
			return 0;
		}
		WaitForSingleObject(pInfo.hThread, -1);
		CloseHandle(pInfo.hThread);
		CloseHandle(pInfo.hProcess);
		logger.log("Process created successfully.");
		return 0;
	}
}