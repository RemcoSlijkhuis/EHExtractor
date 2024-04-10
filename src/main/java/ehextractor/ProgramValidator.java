package ehextractor;

import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;

public class ProgramValidator {

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

	private static boolean checkProcessorBitness(Program program, Logger logger) {

		CompilerSpec compilerSpec = program.getCompilerSpec();
    	Language sourceLanguage = compilerSpec.getLanguage();

    	// Some extra things.
    	//println("Language used: " + sourceLanguage);
    	//if (sourceLanguage.isBigEndian()) {
        //	println("  Big Endian");
    	//}
    	//else {
        //	println("  Little Endian");
    	//}
    	//println("Language produced: " + compilerSpec.getDecompilerOutputLanguage());
    	
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
