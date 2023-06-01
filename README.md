# Dynamic (Not) Linked Library Injector
## Simplistic multipurpose dll injector utilizing Microsoft Detours.
dnll-injector is a console application for injecting dlls into 32/64-bit processes.
It can create processes while injecting dlls into the import table or inject dlls into running processes.
# How to use
### Basics:
1. Pass the path to the process's executable to dnll-injector.exe, be that via cmd or dragging and dropping.
2. A file called dnll-injector-target.txt will be created, containing the path to the executable.
3. The path inside the file is used for any further invocations of dnll-injector. It can be overriden by passing other executables.
### Injecting into an existing process:
After the target path has been set (or is specified as an argument), any path to any dll passed to dnll-injector will be used to
attempt an injection. Keep in mind 32 and 64-bit process and dll incompatibility. If multiple processes with the same name exist,
you'll be prompted to choose one by its process id (PID).
### Creating and injecting into a process:
If the target executable isn't currently running, dnll-injector will attempt to create a process with the input dlls. 
Note that the input dlls' entrypoint will be called, executing all of its code. Some dlls are not meant to be loaded this early.
Follow the Microsoft guidelines for dllmain contents. 
### IMPORTANT:
To be able to create a process with injected dlls, all of them NEED TO EXPORT AT LEAST ONE FUNCTION. 
You can copy the following function into your dll:
```cpp
__declspec(dllexport) void dummyExport() {}
```
The function contents do not matter as it will not be called, it is only used for the import table injection.
# WARNING:
### I AM NOT RESPONSIBLE FOR ANY POTENTIAL DAMAGES CAUSED BY THIS TOOL OR ITS MISUSE
