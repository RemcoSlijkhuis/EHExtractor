package ehextractor;

import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;

/**
 * Class providing methods to validate if a program can be analyzed by EHExtractor.
 */
public class ProgramValidator {

	/**
     * Checks if the given program was compiled with MSVC and is intended for a 32-bit x86 architecture. If so, it can be analyzed by EHExtractor.
     * @param program The program to check.
     * @param logger The logger to use for logging details about the checks.
     * @return true if the program can be analyzed, false otherwise.
     */
	public static boolean canAnalyze(Program program, Logger logger) {

    	if (!checkCompiler(program, logger)) {
    		if (logger != null)
    			logger.log(Level.INFO, "This executable was not compiled using MSVC.");
    		return false;
    	}

    	if (!checkProcessorBitness(program, logger)) {
    		if (logger != null)
    			logger.log(Level.INFO, "Executable should be for 32-bit x86, but is not.");    		
    		return false;
    	}

    	if (logger != null)
    		logger.log(Level.INFO, "Executable is for 32-bit x86 and is compiled using MSVC.");
    	return true;
    }

	/**
     * Checks if the compiler used for the given program is MSVC.
     * @param program The program to check.
     * @param logger The logger to use for logging details about the check.
     * @return true if the program was compiled with MSVC, false otherwise.
     */
	private static boolean checkCompiler(Program program, Logger logger) {

		String usedCompiler = program.getCompiler();
    	CompilerSpec compilerSpec = program.getCompilerSpec();
    	CompilerSpecDescription compilerSpecDescription =  compilerSpec.getCompilerSpecDescription();
    	String compilerSpecName = compilerSpecDescription.getCompilerSpecName();
    	CompilerSpecID compilerSpecID = compilerSpecDescription.getCompilerSpecID();

    	if (logger != null)
    		logger.log(Level.FINE, "Compiler check");

    	if (!usedCompiler.startsWith("visualstudio:")) {
    		return false;
    	}

    	if (!(compilerSpecName.equals("Visual Studio") && compilerSpecID.toString().equals("windows"))) {
    		return false;
    	}

    	return true;
	}

	/**
     * Checks if the given program is intended for a 32-bit x86 processor.
     * @param program The program to check.
     * @param logger The logger to use for logging details about the check.
     * @return true if the program is for a 32-bit x86 processor, false otherwise.
     */
	private static boolean checkProcessorBitness(Program program, Logger logger) {

		CompilerSpec compilerSpec = program.getCompilerSpec();
    	Language sourceLanguage = compilerSpec.getLanguage();
    	  	Processor processor = sourceLanguage.getProcessor();
    	int pointerSize = sourceLanguage.getDefaultDataSpace().getPointerSize();

    	if (logger != null) {
        	logger.log(Level.FINE, "Processor & bitness check:");
        	logger.log(Level.FINE, "  Processor type: " + processor);
        	logger.log(Level.FINE, "  Pointer size: " + 8*pointerSize + " bits");
    	}

		return processor.toString().equals("x86") && pointerSize == 4;
	}

}
