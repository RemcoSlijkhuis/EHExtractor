package instructionpattrns;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

/**
 * Utility class to facilitate matching a list of instruction patterns against
 * an instruction iterator. This class is used to determine if a sequence of
 * instructions matches a defined pattern.
 */
public class InstructionPatterns {

	/**
     * Matches a list of instruction patterns against instructions from an instruction iterator.
     *
     * @param instructionPatterns A list of instruction patterns to be matched.
     * @param instIter An instruction iterator providing the instructions to match against.
     * @param ignoreNops If true, NOP instructions will be ignored during the matching process.
     * @return A MatchResult object indicating if the match was successful and the address after the last matched instruction, or the first instruction's address if the match was unsuccessful.
     */
	public static MatchResult match(List<InstructionPattern> instructionPatterns, InstructionIterator instIter, boolean ignoreNops) {
		Logger logger = Logger.getLogger("EHExtractor");

		boolean matched = false;     
		Address startAddress = null;
        MatchResult matchResult = new MatchResult(matched, startAddress);
        
        var nop = new NopInstructionPattern();
        
        int instPatternInd = 0;
        int actualInstInd = 0;
        while (instIter.hasNext()) {
        	Instruction inst = instIter.next();
        	logger.log(Level.FINE, String.format("%02d  ", actualInstInd) + inst.toString());

        	// Store the address of the first instruction. If we don't have match, the start address is the address we should return.
        	if (startAddress == null) {
        		startAddress = inst.getAddress();
        		matchResult = new MatchResult(matched, startAddress);
        	}
        	
        	// Ignore NOPs if needed.
        	// TODO Handle the case where ignoreNops is true but one of the instruction patterns is actually a NOP.
        	if (ignoreNops) {        		
        		if (nop.matches(inst) ) {
        			actualInstInd++;
        			continue;
        		}
        	}
        	
        	// Do the pattern and the instruction match?
        	if (!instructionPatterns.get(instPatternInd).matches(inst)) {
        		// No match.
        		matched = false;
        		matchResult = new MatchResult(matched, startAddress);
        		logger.log(Level.FINER, "Instructions not matched.");
    			break;
        	}

        	// There is a match. Advance the instruction and pattern pointers.
        	instPatternInd++;
        	actualInstInd++;

        	// Have we matched all patterns?
    		if (instPatternInd == instructionPatterns.size()) {
    			matched = true;
    			// Get the next address after the final matched instruction. 
    			// Easy way to get the address after the current instruction possible?
    			Address nextAddress = null;
    			var nextInst = inst.getNext();
    			if (nextInst != null) {
    				nextAddress = nextInst.getAddress();
    			}
    			else {
    				nextAddress = inst.getAddress().add(inst.getLength());
    			}

        		matchResult = new MatchResult(matched, nextAddress);
        		logger.log(Level.FINER, "All instructions matched.");
    			break;
    		}
        }

        return matchResult;
    }

}
