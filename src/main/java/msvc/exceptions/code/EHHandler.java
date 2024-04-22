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

import ehextractor.FunctionUtils;
import instructionpattrns.AddressInstructionPattern;
import instructionpattrns.InstructionPattern;
import instructionpattrns.InstructionPatterns;
import instructionpattrns.MatchResult;
import instructionpattrns.RegisterInstructionPattern;
import instructionpattrns.ScalarInstructionPattern;

/**
 * Class for looking for exception handling setup code and extracting FuncInfo addresses.
 */
public class EHHandler {

	private Program program = null; // I don't like this at all, but it is needed for makeAddress.
	Listing listing = null;
	private Function cxxFrameHandler3 = null;
	private Function securityCheckCookie = null;
	private boolean allOk;

	private Logger logger = null;

	/**
     * Initializes an EHHandler object for the given program.
     * 
     * @param program The program to analyze for exception handling setup-related code.
     */
	public EHHandler(Program program) {
		logger = Logger.getLogger("EHExtractor");
		this.program = program;
		this.listing = program.getListing();
		
		allOk = initialize();		
	}
	
	public boolean isAllOk() {
		return allOk;
	}

	/**
     * Attempts to find functions essential for exception handling such as
     * CxxFrameHandler3 (mandatory) and security_check_cookie (optional).
     * 
     * @return true if all necessary functions are found, false otherwise.
     */
	private boolean initialize() {
		// If there are exceptions, we expect an exception handler. The main one for x86
		// is CxxFrameHandler3. We should look for this; note: could have thunks.
		//
		// Find the function vcruntime*CxxFrameHandler3.
		logger.log(Level.FINE, "Determining the address of (thunk) function *CxxFrameHandler3.");
		cxxFrameHandler3 = FunctionUtils.findFunction(program, "CxxFrameHandler3", "vcruntime", true);
		if (cxxFrameHandler3 == null) {
			logger.log(Level.INFO, "Main exception handler function not found.");
			return false;
		}

		// If security cookies have been used, there should be a function called "security_check_cookie".
		// We don't know if they have been used, so we don't know if we'll find this function.
		// Also, when this function is present, it is sometimes present more than once.
		// In any case, whether we find 'one' function with this name or not, we'll carry on.    		
		logger.log(Level.FINE, "Looking up a security_check_cookie function.");
		securityCheckCookie = FunctionUtils.findFunction(program, "security_check_cookie", null, true);
		if (securityCheckCookie != null) {
			logger.log(Level.FINE, "Found a security_check_cookie function: " + securityCheckCookie.getName() + " @" + securityCheckCookie.getEntryPoint());
		}
		else {
			logger.log(Level.FINE, "No clear security_check_cookie function found.");			
		}

		return true;		
	}
	
	
	/**
     * Tries to extract the address pointing to the FuncInfo data structure from
     * EH registration code starting at ehSetupAddress
     * 
     * @param ehSetupAddress The starting address of the EH setup code.
     * @return The FuncInfo address, or null if not found.
     */
	public Address extractFuncInfoAddress(Address ehSetupAddress) {
		Address startAddress = ehSetupAddress;

		// Check for cookie-checking code.
		var matchResult = lookForCookieCheckingCode(listing, startAddress, securityCheckCookie);

		// Note: If no cookie-checking code, getNextAddress() will return the original start address.
		// If there is cookie-checking code, getNextAddress() will return the first address after this code,
		// however many times the cookie was checked.
		InstructionIterator instIt = listing.getInstructions(matchResult.getNextAddress(), true);

		// Exception handler function info registration.
		List<InstructionPattern> regInstructions = Arrays.asList(
				new ScalarInstructionPattern("MOV", "EAX", Scalar.class),
				new AddressInstructionPattern("JMP", cxxFrameHandler3, true)
		);

		logger.log(Level.FINE, "Looking for matching EH handler registration instructions.");
		if (!InstructionPatterns.match(regInstructions, instIt, true).isMatched()) {
			logger.log(Level.INFO, "EH handler registration instructions not found.");
			return null;
		}
		logger.log(Level.INFO, "EH handler registration instructions found.");

		Scalar scalar = ((ScalarInstructionPattern)regInstructions.get(0)).getActualScalar();
		var ehFuncInfoAddress = makeAddress(scalar.getUnsignedValue());
		logger.log(Level.INFO, "Determined ehFuncInfoAddress: " + ehFuncInfoAddress);
		return ehFuncInfoAddress;
	}
	
	/**
     * Searches for instructions associated with security cookie checks starting from a given address.
     * 
     * @param listing The program listing to search within.
     * @param startAddress The address to start the search from.
     * @param securityCheckCookie The function associated with security cookie checks.
     * @return A MatchResult indicating if such instructions were found and if true, the address immediately after the matched code and startAddress otherwise.
     */
	private MatchResult lookForCookieCheckingCode(Listing listing, Address startAddress, Function securityCheckCookie) {
		// Generic/flexible base cookie-checking code instructions.
		// If there is cookie-checking, the following code will be there at the start.
		List<InstructionPattern> baseCookieCheckInstructions = Arrays.asList(
				new AddressInstructionPattern("MOV", "EDX", "ESP", Scalar.class),
				new AddressInstructionPattern("LEA", "EAX", "EDX", (long)0xc),			
				new AddressInstructionPattern("MOV", "ECX", "EDX", Scalar.class), 
				new RegisterInstructionPattern("XOR", "ECX", "EAX"),
				new AddressInstructionPattern("CALL", securityCheckCookie, true)
		);

		// Generic/flexible additional cookie-checking code instructions.
		// If there is mode cookie-checking going on, the following code will
		// be there, possibly multiple times.
		List<InstructionPattern> additionalCookieCheckInstructions = Arrays.asList(
				new AddressInstructionPattern("MOV", "ECX", "EDX", Scalar.class), 
				new RegisterInstructionPattern("XOR", "ECX", "EAX"),
				new AddressInstructionPattern("CALL", securityCheckCookie, true)
		);

		// Look for base cookie-checking code.
		logger.log(Level.FINE, "Looking for base security cookie-checking code.");
		InstructionIterator instIt = listing.getInstructions(startAddress, true);
		MatchResult matchResult = InstructionPatterns.match(baseCookieCheckInstructions, instIt, true);
		if (!matchResult.isMatched()) {
			logger.log(Level.FINE, "Base cookie checking instructions not found.");
			return new MatchResult(false, startAddress);
		}
		logger.log(Level.FINE, "Base cookie checking instructions found.");
		startAddress = matchResult.getNextAddress();

		// There IS base cookie-checking code. Is it followed by additional cookie-checking code?
		// Note that we don't know how many instances of additional cookie-checking code there can be.
		logger.log(Level.FINE, "Looking for additional security cookie-checking code.");
		while (matchResult.isMatched()) {
			instIt = listing.getInstructions(startAddress, true);
			matchResult = InstructionPatterns.match(additionalCookieCheckInstructions, instIt, true);
			if (matchResult.isMatched()) {
				logger.log(Level.FINE, "Additional cookie checking instructions found.");
				startAddress = matchResult.getNextAddress();
			}
		}
		logger.log(Level.FINE, "Additional cookie checking instructions not found.");
		return new MatchResult(true, startAddress);		
	}

    /**
     * Converts a long value to an Address object.
     * 
     * @param address The long value representing the address.
     * @return The Address object corresponding to the provided long value.
     */
	// TODO: Get rid of this function here.
    private Address makeAddress(long address) {
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
		Address newAddress = defaultAddressSpace.getAddress(address);
		return newAddress;
    }

}
