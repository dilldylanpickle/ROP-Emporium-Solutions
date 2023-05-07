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
### For each challenge, I have provided two different solutions: 
- `Flag Solution` prints out the flag provided in the directory (Some flags are decrypted with the data files)
- `Shell Solution` spawns a bourne shell to allow hypothetical remote code execution

one that prints out the flag and one that gets a shell. Additionally, each solution includes offset calculations, ASLR compatibility, and detailed comments to help understand the code.

- `Challenge 1 - ret2win` (https://ropemporium.com/challenge/ret2win.html)
  - [Flag Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_1/ret2win32.py) (x86)
  - [Flag Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_1/ret2win64.py) (x86_64)
  - Shell Solution TBA (x86)
  - Shell Solution TBA (x86_64)
- `Challenge 2 - split` (https://ropemporium.com/challenge/split.html)
  - [Flag Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_2/split32.py) (x86)
  - [Flag Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_2/split64.py) (x86_64)
  - Shell Solution TBA (x86)
  - Shell Solution TBA (x86_64)
- `Challenge 3 - callme` (https://ropemporium.com/challenge/callme.html)
  - [Flag Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_3/callme32.py) (x86)
  - [Flag Solution](https://github.com/dilldylanpickle/ROP-Emporium-Solutions/blob/main/Challenge_3/callme64.py) (x86_64)
  - Shell Solution TBA (x86)
  - Shell Solution TBA (x86_64)
- `Challenge 4 - write4`
  - Flag Solution TBA (x86)
  - Flag Solution TBA (x86_64)
  - Shell Solution TBA (x86)
  - Shell Solution TBA (x86_64)
- `Challenge 5 - badchars`
  - Flag Solution TBA (x86)
  - Flag Solution TBA (x86_64)
  - Shell Solution TBA (x86)
  - Shell Solution TBA (x86_64)
- `Challenge 6 - fluff`
  - Flag Solution TBA (x86)
  - Flag Solution TBA (x86_64)
  - Shell Solution TBA (x86)
  - Shell Solution TBA (x86_64)
- `Challenge 7 - pivot`
  - Flag Solution TBA (x86)
  - Flag Solution TBA (x86_64)
  - Shell Solution TBA (x86)
  - Shell Solution TBA (x86_64)
- `Challenge 8 - ret2csu`
  - Flag Solution TBA (x86)
  - Flag Solution TBA (x86_64)
  - Shell Solution TBA (x86)
  - Shell Solution TBA (x86_64)

Each challenge has its own directory containing the exploit script, any additional files needed, and a README file describing the challenge and my approach to solving it.

Feel free to use my solutions as a reference, but try to solve the challenges on your own first!
