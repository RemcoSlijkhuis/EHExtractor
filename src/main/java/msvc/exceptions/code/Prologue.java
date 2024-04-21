package msvc.exceptions.code;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;

import instructionpattrns.InstructionPattern;
import instructionpattrns.InstructionPatterns;
import instructionpattrns.RegisterInstructionPattern;
import instructionpattrns.ScalarInstructionPattern;

/**
 * Represents the start (prologue) of a function; analyzes the prologue of functions to identify and extract addresses related to exception handling setup as done by MSVC.
 */
public class Prologue {
	
	private Program program = null;
	Listing listing = null;
	Logger logger = null;

    // Function start instructions (patterns).
	private static final List<InstructionPattern> startInstructions = Arrays.asList(
			new RegisterInstructionPattern("PUSH", Arrays.asList("EBP")),
			new RegisterInstructionPattern("MOV", Arrays.asList("EBP", "ESP")));

    // Exception handling start instructions (patterns). The rest of the EH-setup 
	// instructions are only relevant during runtime so they are ignored here.
    private static final List<InstructionPattern> ehStartInstructions = Arrays.asList(
    		new ScalarInstructionPattern("PUSH", -1),
    		new ScalarInstructionPattern("PUSH", null)); 

    /**
	 * Constructs a Prologue instance for the given program.
	 * 
	 * @param program The program to analyze.
	 */
    public Prologue(Program program) {
		logger = Logger.getLogger("EHExtractor");
		this.program = program;
		this.listing = program.getListing();
	}
	
    /**
	 * Attempts to extract the address where the code begins that registers a FuncInfo structure and that starts the main exception handler for the given function.
	 * 
	 * @param func The function to analyze.
	 * @return The address of the exception handling setup/registration code if found, otherwise null.
	 */
    public Address extractEHSetupAddress(Function func) {
		InstructionIterator instIter = listing.getInstructions(func.getBody(), true);

		logger.log(Level.FINE, "Looking for standard function prologue.");
		if (!InstructionPatterns.match(startInstructions, instIter, false).isMatched()) {
			logger.log(Level.INFO, "Normal start instructions not found!");
			return null;
		}  
		logger.log(Level.INFO, "Normal start instructions found!");

		logger.log(Level.FINE, "Looking for exception handling start instructions.");
		if (!InstructionPatterns.match(ehStartInstructions, instIter, false).isMatched()) {
			logger.log(Level.INFO, "Exception handling start instructions not found!");
			return null;
		}
		logger.log(Level.INFO, "Exception handling start instructions found!");

		// Determine the address that's pushed onto the stack.
		Scalar ehPointer = ((ScalarInstructionPattern)ehStartInstructions.get(1)).getActualScalar();
		Address ehSetupAddress = makeAddress(ehPointer);
		return ehSetupAddress;
	}

    /**
     * Converts a scalar value to an Address object.
     * 
     * @param scalar The scalar value representing the address.
     * @return The Address object corresponding to the provided scalar value.
     */
	private Address makeAddress(Scalar scalar) {
		// TODO return toAddr(scalar.getUnsignedValue());
    	return makeAddress(scalar.getUnsignedValue());
    }

    /**
     * Converts a long value to an Address object.
     * 
     * @param address The long value representing the address.
     * @return The Address object corresponding to the provided long value.
     */
    private Address makeAddress(long address) {
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
		Address newAddress = defaultAddressSpace.getAddress(address);
		return newAddress;
    }
}
