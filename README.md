# EHExtractor for Ghidra

EHExtractor offers both an analyzer and a script for the reverse engineering framework [Ghidra](https://ghidra-sre.org/), that extract exception handling (EH) information from x86 binaries produced by the Microsoft Visual C++ compiler.

It was created as part of a research effort to improve the decompilation of C++ code at the *Open Universiteit* in the Netherlands.

The main contributor is [Remco Slijkhuis](https://github.com/RemcoSlijkhuis).

## Features

* Produces an overview of the try/catch block layout for each function with such constructs.
* The overview contains all information that can be determined from the underlying EH data structures, including state values of try and catch blocks, catch block addresses and catch block exception types.
* The overview can be output to a file (analyzer, script) and to the Ghidra console (script).

The following is an example of the output EHExtractor produces, showing a function's nested try and catch block layout.

```
/* TryBlockMapEntry [5]	1-5,12,1 */
Try (state=1) {
  /* TryBlockMapEntry [1]	2-4,5,1 */
  Try (state=2) {
    /* TryBlockMapEntry [0]	3-3,4,1 */
    Try (state=3) {}
    Catch (std::logic_error) (state=4)	@0x0040196b {}
  }
  Catch (CustomException1) (state=5)	@0x0040198c {}
}
Catch (...) (state=6)	@0x004019b0 {
  /* TryBlockMapEntry [4]	7-7,12,2 */
  Try (state=7) {}
  Catch (std::out_of_range) (state=8)	@0x004019c2 {}
  Catch (...) (state=8)	@0x004019f5 {}
  ToBeNestedInCatches {
    /* TryBlockMapEntry [3]	11-11,12,1 */
    Try (state=11) {}
    Catch (...) (state=12)	@0x00401a05 {}
    /* TryBlockMapEntry [2]	9-9,10,1 */
    Try (state=9) {}
    Catch (...) (state=10)	@0x004019d2 {}
  }
}
```

## Installation instructions

#### Analyzer

- Download the ghidra*.zip file from the [dist](/dist) directory.
- Start Ghidra.
- From the Project window, click File/Install Extensions...
- Click the + icon (top right) and navigate to the location of the ghidra*.zip file. Select the file and click OK.
- After installation, click OK and restart Ghidra.

#### Script

Running the script requires not only a working installation of Ghidra, but also of Eclipse and the GhidraDev plugin which provides a bridge between Ghidra and Eclipse.

- Install Eclipse (https://eclipseide.org/).
- Install GhidraDev by following the instructions in the [Ghidra installation guide](https://ghidra-sre.org/InstallationGuide.html#Development).
- Use GhidraDev in Eclipse to create a new Ghidra Module Project.
- Copy the contents of the EHExtractor repository over the project folder.


## Usage

#### Analyzer

- Start Ghidra and open the binary you want to analyze.
- Select Analysis/Auto Analyze from the menu.
- If the binary has not been analyzed before (or previous results were not saved):
	- Run the standard set of analyzers on it first.
	- Follow this up with a single or one-shot run of the "Shared Return Calls" analyzer. This analyzer is part of the standard set of analyzers but was found to miss some crucial aspects of the binary when run together with the other analyzers.
- Select EHExtractor and enabled it if not yet enabled<sup>1</sup>.
- Adjust the minimum logging level and the location of the output file to your liking. (See the [options](#options) section for an explanation of the possible values.)
- Click Analyze. The analyzer output will be written to the log file.

<sup>1</sup><span style="font-size:0.75em;"> If the opened binary is not an x86 MSVC-compiled binary, the analyzer will not be listed.</span>

#### Script
- Adjust the minimum logging level and the location of the output file in the script file in Eclipse to your liking<sup>2</sup>. (See the [options](#options) section for an explanation of the possible values.)
- Open the Ghidra Module Project in Eclipse and go to the ghidra_scripts folder.
- Select EHExtractor.java and then "Run As Ghidra"; this will start up Ghidra and do the necessary setup to connect the project to Ghidra.
- Select the binary you wish to analyze. Ghidra will now open completely
- If the binary has not been analyzed before (or previous results were not saved):
	- Select Analysis/Auto Analyze from the menu.
	- Run the standard set of analyzers on it first.
- Go to the Script Manager (Window/Script Manager) and open the folder "**TODO: choose the folder for the script!**".
- Run EHExtractor by double-clicking on it or selecting it and clicking the green play button. The analyzer output will be written to the log file and to the Ghidra console.

<sup>2</sup><span style="font-size:0.75em;"> Once Ghidra has started, the minimum log level and output file location can be changed in Eclipse without having to restart Ghidra; the changed settings will be used the next time the script is run.</span>

## Options

Log file path: The path to the log file. If the file already exists, new output will be appended to it.

Minimum log level: INFO is the default value and intended for everyday use. Anything lower than INFO (FINE and FINER) will give increasingly more output details (useful for debugging).


