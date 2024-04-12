package instructionpattrns;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class InstructionPatterns {

	public static boolean match(List<InstructionPattern> instructionPatterns, InstructionIterator instIter, boolean ignoreNops) {
		Logger logger = Logger.getLogger("EHExtractor");

		boolean matched = false;     
        var nop = new NopInstructionPattern();
        
        int instPatternInd = 0;
        int actualInstInd = 0;
        while (instIter.hasNext()) {  //! && !monitor.isCancelled()) {
        	Instruction inst = instIter.next();
        	logger.log(Level.FINE, String.format("%02d  ", actualInstInd) + inst.toString());

        	// TODO Handle the case where ignoreNops is true but one of the instruction patterns is actually a NOP.
        	if (ignoreNops) {        		
        		if (nop.matches(inst) ) {
        			actualInstInd++;
        			continue;
        		}
        	}
        	
        	if (!instructionPatterns.get(instPatternInd).matches(inst)) {
        		matched = false;
        		logger.log(Level.FINER, "Instructions not matched!");
    			break;
        	}

        	instPatternInd++;
        	actualInstInd++;

    		if (instPatternInd == instructionPatterns.size()) {
    			matched = true;
    			logger.log(Level.FINER, "All instructions matched!");
    			break;
    		}

        }
	    	
    	return matched;
    }

}
