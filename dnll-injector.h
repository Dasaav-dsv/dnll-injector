#pragma once

#ifdef _MSC_VER
#pragma comment (lib, "detours")
#endif

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "Windows.h"
#include "Tlhelp32.h"

#include "detours-4.0.1/detours.h"

#include <vector>
#include <memory>
#include <fstream>
#include <iostream>
#include <filesystem>

#include "Logger.h"