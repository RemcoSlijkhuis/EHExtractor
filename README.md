# EHExtractor for Ghidra

EHExtractor is a script for the reverse engineering framework [Ghidra](https://ghidra-sre.org/) that extracts exception handling (EH) information from 32-bit x86 binaries produced by the Microsoft Visual C++ compiler.

It was created as part of a research effort to improve the decompilation of C++ code at the *Open Universiteit* in the Netherlands.

The main contributor is [Remco Slijkhuis](https://github.com/RemcoSlijkhuis).

## Features

* Produces an overview of the try/catch block layout for each function with such constructs.
* The overview contains all information that can be determined from the underlying EH data structures, including state values of try and catch blocks, catch block addresses and catch block exception types.
* The overview can be output to the Ghidra console and to a file.

## Installation instructions

Running this script requires a working installation of Ghidra, the GhidraDev plugin and Eclipse.

To install Ghidra, follow the [Ghidra installation guide](https://ghidra-sre.org/InstallationGuide.html).
The installation guide also contains information about installing the [GhidraDev](https://ghidra-sre.org/InstallationGuide.html#Development) plugin which provides a bridge between Ghidra and Eclipse.

Use GhidraDev in Eclipse to create a new Ghidra Module Project and copy the contents of this repository over the project folder.

## Usage

Open the Ghidra Module Project in Eclipse and go to the ghidra_scripts folder.

Select EHExtractor.java and then "Run As Ghidra"; this will start up Ghidra and do the necessary setup to connect the project to Ghidra.

The script will now be available in the 

