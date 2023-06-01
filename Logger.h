#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <filesystem>
#include <iostream>
#include <cstdarg>
#include <string>
#include <memory>

class Logger {
public:
	static Logger& get() noexcept {
		static Logger s;
		return s;
	}

	// Log the specified string with printf formatting options in the log file and console.
	void log(std::string log, ...) noexcept {
		va_list extra_args;
		va_start(extra_args, log);
		std::string fullLog = "dnll-injector: ";
		fullLog += log + "\n";
		if (Logger::logFile) {
			vfprintf(Logger::logFile, fullLog.c_str(), extra_args);
			fflush(Logger::logFile);
		}
		vprintf(fullLog.c_str(), extra_args);
		va_end(extra_args);
	}

	// As Logger is a singleton, the assignment and copy operators are deleted.
	Logger(const Logger&) = delete;
	Logger& operator = (const Logger&) = delete;

private:
	Logger() {
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		fopen_s(&Logger::logFile, (std::filesystem::path{ path }.parent_path().generic_string() + "/dnll-injector.log").c_str(), "w");
	}

	~Logger() {}
		
	static inline FILE* logFile{};
};