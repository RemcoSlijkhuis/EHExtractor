package instructionpattrns;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

/**
 * Represents an instruction pattern for matching instructions that involve registers.
 */
public class RegisterInstructionPattern extends InstructionPattern {

	String mnemonic = null;
	List<String> operands = null;
	
	/**
     * Creates an instruction pattern for matching instructions with a specific mnemonic and two specific registers (e.g. XOR ECX, EAX).
     *
     * @param mnemonic The instruction mnemonic to match.
     * @param register1 The first register to match in the instruction.
     * @param register2 The second register to match in the instruction.
     */
	public RegisterInstructionPattern(String mnemonic, String register1, String register2) {
		this.mnemonic = mnemonic;		
		this.operands = Arrays.asList(register1, register2);
	} //"MOV", Arrays.asList("EBP", "ESP")

	/**
     * Creates an instruction pattern for matching instructions with a specific mnemonic and one or more specific registers (e.g. PUSH ESP; MOV EBP, ESP).
     *
     * @param mnemonic The instruction mnemonic to match.
     * @param operands A list of registers (as strings) to match in the instruction, in given order.
     */
	public RegisterInstructionPattern(String mnemonic, List<String> operands) {
		this.mnemonic = mnemonic;
		this.operands = operands;
	}

	/**
     * Checks if the provided instruction matches this instruction pattern.
     *
     * @param inst The instruction to be checked.
     * @param instContext The instruction context of the instruction.
     * @param instProto The instruction prototype of the instruction.
     * @return true if the instruction matches the instruction pattern, false otherwise.
     */
	@Override
	protected boolean matchesImpl(Instruction inst, InstructionContext instContext, InstructionPrototype instProto) {

		// Do the mnemonic and number of operands match?
		if (!instProto.getMnemonic(instContext).equals(this.mnemonic))
			return false;
		if (instProto.getNumOperands() != this.operands.size())  //2)
			return false;

		// Check the operands. They should all be registers (and then the right ones).
		for (int opInd=0; opInd<this.operands.size(); opInd++) {
			Object[] opObjects = instProto.getOpObjects(opInd, instContext);
			if (opObjects.length != 1)
				return false;
			
			Register reg = toRegister(opObjects[0]);
			if (reg == null || !reg.getName().equals(this.operands.get(opInd))) {
				Logger.getLogger("EHExtractor").log(Level.FINE, "Issue with register " + opInd);
				return false;
			}
		}

		return true;
	}

}
