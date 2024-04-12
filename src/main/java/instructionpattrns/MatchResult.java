package instructionpattrns;

import ghidra.program.model.address.Address;

public class MatchResult {
    private boolean matched;
    private Address nextAddress;

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
