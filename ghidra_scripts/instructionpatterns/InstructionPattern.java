package instructionpatterns;

import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.ParserContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;

public abstract class InstructionPattern {
	public final boolean matches(Instruction inst) {
		InstructionInfo instInfo = getInstructionInfo(inst);
		if (instInfo == null)
		   	return false;

		return matchesImpl(inst, instInfo.getInstructionContext(), instInfo.getInstructionPrototype());
	}
	
	protected abstract boolean matchesImpl(Instruction inst, InstructionContext instContext, InstructionPrototype instProto);
	
	public Register toRegister(Object opObject) {
		if (opObject instanceof Register) {
			return (Register) opObject;
		}
		return null;
	}
	
	public Scalar toScalar(Object opObject) {
		if (opObject instanceof Scalar) {
			return (Scalar) opObject;
		}
		return null;
	}

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

	private class InstructionInfo {
	    private InstructionContext instructionContext;
	    private InstructionPrototype instructionPrototype;

	    public InstructionInfo(InstructionContext instructionContext, InstructionPrototype instructionPrototype) {
	        this.instructionContext = instructionContext;
	        this.instructionPrototype = instructionPrototype;
	    }

	    // Getters
	    public InstructionContext getInstructionContext() {
	        return instructionContext;
	    }

	    public InstructionPrototype getInstructionPrototype() {
	        return instructionPrototype;
	    }
	}

}
