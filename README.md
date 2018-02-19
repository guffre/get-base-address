# get-base-address

Gets the base address of an executable or module loaded in memory.
I needed a way to get the base address before running ReadProcessMemory(), and this little program does the trick.

This also includes a function I call SetPriv, which modifies token privileges on Windows. The reason this functionality is included is incase you are trying to get the base address of a system process, you will first need to set the SeDebugPrivilege.
