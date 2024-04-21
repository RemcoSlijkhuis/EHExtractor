package instructionpattrns;

import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.ParserContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;

/**
 * Abstract base class for instruction patterns, with functionality for matching with an actual instruction.
 */
public abstract class InstructionPattern {
	/**
     * Checks if the given instruction matches an instruction pattern.
     * This is the main function to call for matching; it will call the specific
     * implementation logic internally.
     * 
     * @param inst The instruction to check against the instruction pattern.
     * @return true if the instruction matches the instruction pattern, false otherwise.
     */
	public final boolean matches(Instruction inst) {
		InstructionInfo instInfo = getInstructionInfo(inst);
		if (instInfo == null)
		   	return false;

		return matchesImpl(inst, instInfo.getInstructionContext(), instInfo.getInstructionPrototype());
	}
	
	/**
     * Abstract method to be implemented by a subclass, defining the specific matching logic for that subclass.
     * 
     * @param inst The instruction being checked.
     * @param instContext The instruction's instruction context.
     * @param instProto The instruction's instruction prototype.
     * @return true if the instruction matches according to the specific subclass matching logic.
     */
	protected abstract boolean matchesImpl(Instruction inst, InstructionContext instContext, InstructionPrototype instProto);
	
	/**
     * Converts an 'Object object' to a Register object if possible.
     * 
     * @param opObject The object to convert.
     * @return A Register object if conversion is possible, null otherwise.
     */
	public Register toRegister(Object opObject) {
		if (opObject instanceof Register) {
			return (Register) opObject;
		}
		return null;
	}
	
	/**
     * Converts an 'Object object' to a Scalar object if possible.
     * 
     * @param opObject The object to convert.
     * @return A Scalar object if conversion is possible, null otherwise.
     */
	public Scalar toScalar(Object opObject) {
		if (opObject instanceof Scalar) {
			return (Scalar) opObject;
		}
		return null;
	}

	/**
     * Extracts instruction context and instruction prototype information for the given instruction, used in instruction pattern matching.
     * 
     * @param inst The instruction from which to extract information.
     * @return An InstructionInfo object containing instruction context and instruction prototype, or null if an error occurs.
     */
	private InstructionInfo getInstructionInfo(Instruction inst) {
	    InstructionContext instContext = inst.getInstructionContext();
	    try {
	    	ParserContext parserContext = instContext.getParserContext();
	    	InstructionPrototype instProto = parserContext.getPrototype();
	    	return new InstructionInfo(instContext, instProto);
		} catch (MemoryAccessException e) {
		    return null;
		}
	}

	/**
     * Helper class to hold instruction context and instruction prototype information.
     */
	private class InstructionInfo {
	    private InstructionContext instructionContext;
	    private InstructionPrototype instructionPrototype;

	    public InstructionInfo(InstructionContext instructionContext, InstructionPrototype instructionPrototype) {
	        this.instructionContext = instructionContext;
	        this.instructionPrototype = instructionPrototype;
	    }

	    public InstructionContext getInstructionContext() {
	        return instructionContext;
	    }

	    public InstructionPrototype getInstructionPrototype() {
	        return instructionPrototype;
	    }
	}

}
