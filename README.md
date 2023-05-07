# ROP Emporium Solutions

This repository contains my solutions to all the ROP Emporium challenges, utilizing only pwntools, gdb, and radare2. I completed these challenges on WSL2 Ubuntu-20.04 Yes, all these exploits worked inside WSL2! All of these python scripts are "autopwnable" so every script handles offset calculations, ROP chain constructions, etc. I did't hard code addresses because I completed these challenges with ASLR enabled. All you have to do is run the script and the flag is printed!

Check out my Linux exploit development tool ROPcheck!
 - Ropcheck Version 2.0 (https://github.com/dilldylanpickle/ROPcheck)

## Dependencies

To run the scripts, you will need the following dependencies:
- Python 3.8.10
- Pwntools (https://github.com/Gallopsled/pwntools)
- Radare2 (https://github.com/radareorg/radare2)
- gdb gef (https://github.com/hugsy/gef)

Note that some challenges may have additional dependencies or requirements, as described in their respective README files.

## Usage

To download my solutions along with the challenges, follow these steps:

Step 1. Clone the GitHub Repository
> $ git clone https://github.com/dilldylanpickle/ROP-Emporium-Solutions

Step 2. Change directories into the ROP-Empormium-Solutions directory
> $ cd ROP-Emporium-Solutions/Challenge_1

Step 3. Make the binaries executable with chmod
> $ chmod u+x ret2win

Step 4. Run the pwntools script and get the flag!
> $ python3 ret2win64.py

## Challenge Solutions (x86 and x86_64 solutions only)

- `Challenge 1 - ret2win` (https://ropemporium.com/challenge/ret2win.html)
  - [Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_1/ret2win32.py) (x86)
  - [Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_1/ret2win64.py) (x86_64)
- `Challenge 2 - split` (https://ropemporium.com/challenge/split.html)
  - [Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_2/split32.py) (x86)
  - [Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_2/split64.py) (x86_64)
- `Challenge 3 - callme` (https://ropemporium.com/challenge/callme.html)
  - [Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_3/callme32.py) (x86)
  - [Solution]() (x86_64)
- `Challenge 4 - write4`
  - [Solution]() (x86)
  - [Solution]() (x86_64)
- `Challenge 5 - badchars`
  - [Solution]() (x86)
  - [Solution]() (x86_64) 
- `Challenge 6 - fluff`
  - [Solution]() (x86)
  - [Solution]() (x86_64)
- `Challenge 7 - pivot`
  - [Solution]() (x86)
  - [Solution]() (x86_64)
- `Challenge 8 - ret2csu`
  - [Solution]() (x86)
  - [Solution]() (x86_64)

Each challenge has its own directory containing the exploit script, any additional files needed, and a README file describing the challenge and my approach to solving it.

Feel free to use my solutions as a reference, but try to solve the challenges on your own first!
