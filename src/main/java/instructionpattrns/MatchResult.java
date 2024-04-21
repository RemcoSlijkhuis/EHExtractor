package instructionpattrns;

import ghidra.program.model.address.Address;

/**
 * Represents the result of matching a sequence of instructions against a sequence of instruction patterns.
 */
public class MatchResult {
    private boolean matched;
    private Address nextAddress;

    /**
     * Constructs a new MatchResult.
     *
     * @param matched Indicates whether the match was successful or not.
     * @param nextAddress The address of the next instruction following the last matched instruction, or the address of the start instruction if no match was found. 
     */
    public MatchResult(boolean matched, Address nextAddress) {
        this.matched = matched;
        this.nextAddress = nextAddress;
    }

    public boolean isMatched() {
        return matched;
    }

    public Address getNextAddress() {
        return nextAddress;
    }
}
