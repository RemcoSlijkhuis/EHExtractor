package msvc.exceptions;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

/**
 * A parser for the output produced by EHExtractor, for use in unit tests.
 */
public class NestedStructureParser {
	
    private Stack<Object> stack = new Stack<>();
    //private List<TryBlockMapEntry> uniqueEntries = new ArrayList<>();    
    private CatchHandlerFactory catchHandlerFactory = new CatchHandlerFactory();
    
    private Integer latestTryHigh = null;

    public List<TryBlockMapEntry> parseFile(File file) throws IOException {
    	BufferedReader reader = new BufferedReader(new FileReader(file));
    	return parseFile(reader);
    }

    public List<TryBlockMapEntry> parseFile(String filename) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(filename));
    	return parseFile(reader);
    }

    public List<TryBlockMapEntry> parseFile(BufferedReader reader) throws IOException {
        String line;
        List<TryBlockMapEntry> topLevelEntries = new ArrayList<>();

        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.endsWith("*/"))
        		line = line.substring(0, line.length()-2).trim();
            
            if (line.startsWith("/* TryBlockMapEntry")) {
                parseTryBlockMapEntry(line, topLevelEntries);
            } else if (line.startsWith("Try")) {
                parseTryBlock(line);
            } else if (line.startsWith("Catch")) {
                parseCatchHandler(line);
            } else if (line.startsWith("ToBeNestedInCatches")) {
                parseToBeNestedInCatches(line);
            } else if (line.startsWith("}")) {
                processBlockClosure();
            }
        }
        reader.close();
        return topLevelEntries;
    }
    
    private void parseTryBlockMapEntry(String line, List<TryBlockMapEntry> topLevelEntries) {
        String[] parts = line.split("[\\[\\],-]+");

        var mapIndex = Integer.parseInt(parts[1].trim());
        var tryLow = Integer.parseInt(parts[2].trim());
        var tryHigh = Integer.parseInt(parts[3].trim());
        var catchHigh = Integer.parseInt(parts[4].trim());
        var nCatches = Integer.parseInt(parts[5].trim());

        TryBlockMapEntry entry = new TryBlockMapEntry(mapIndex, tryLow, tryHigh, catchHigh, nCatches);
        
        // Dirty.
        latestTryHigh = tryHigh; 

        Boolean done = false;
        Boolean nested = false;
        while (!done) {
            if (!stack.isEmpty() && stack.peek() instanceof TryBlock) {
                ((TryBlock) stack.peek()).nest(entry);
                done = true;
                nested = true;
            } else if (!stack.isEmpty() && stack.peek() instanceof CatchHandler) {
                ((CatchHandler) stack.peek()).nest(entry);
                done = true;
                nested = true;                
            } else if (!stack.isEmpty() && stack.peek() instanceof TryBlockMapEntry) {
            	stack.pop();
            } else if (!stack.isEmpty() && stack.peek() instanceof List<?>) {
            	((List<TryBlockMapEntry>) stack.peek()).add(entry);
            	done = true;
            	nested = true;
            } else {
            	done = true;
            }
        }
        
        //
        if (!nested)
            topLevelEntries.add(entry);
        
        stack.push(entry);
    }

    private void parseTryBlock(String line) {
		Boolean nesting = false;
		if (line.endsWith("{}")) {
			nesting = false;
    		line = line.substring(0, line.length()-2).trim();
		}
		else if (line.endsWith("{")) {
			nesting = true;
    		line = line.substring(0, line.length()-1).trim();
		}
		else {
			// Ignore, should not happen (...)
		}

        Integer state = parseState(line);
        TryBlock tryBlock = new TryBlock(state, latestTryHigh);
        if (!stack.isEmpty() && stack.peek() instanceof TryBlockMapEntry) {
            ((TryBlockMapEntry) stack.peek()).setTryBlock(tryBlock);
        }
        
        if (nesting)
        	stack.push(tryBlock);
    }

	private void parseCatchHandler(String line) {
		Boolean nesting = false;
		if (line.endsWith("{}")) {
			nesting = false;
    		line = line.substring(0, line.length()-2).trim();
		}
		else if (line.endsWith("{")) {
			nesting = true;
    		line = line.substring(0, line.length()-1).trim();
		}
		else {
			// Ignore, should not happen (...)
		}
		
		String[] parts = line.split("[()\\s]+");
		String exceptionType = parts[1].trim();
		Integer state = parseState(line);
		
		String addressString = parts[parts.length - 1].trim();
		if (addressString.startsWith("@0x"))
			addressString = addressString.substring(3, addressString.length()).trim();
		Integer address = Integer.parseInt(addressString, 16);
		
		CatchHandler catchBlock = catchHandlerFactory.createSimpleCatchHandler(exceptionType, state, address);
	
		if (!stack.isEmpty()) {
			Object parent = stack.peek();
			if (parent instanceof TryBlockMapEntry) {
				((TryBlockMapEntry) parent).addCatchHandler(catchBlock);
			} else {
				// If the top of the stack is not TryBlockMapEntry, we pop items
				// until we find a TryBlockMapEntry or the stack is empty
				while (!stack.isEmpty() && !(stack.peek() instanceof TryBlockMapEntry)) {
					stack.pop();
				}
				if (!stack.isEmpty()) {
					// Now the top is TryBlockMapEntry, so we add the catch to it
					((TryBlockMapEntry) stack.peek()).addCatchHandler(catchBlock);
				}
			}
		}
	
		if (nesting) {
			// Push the catch block on the stack to be able to handle nested TryBlockMapEntries.
			stack.push(catchBlock);
		}
		else {
			// No nesting; no need to push this item on the stack.
		}		
	}

	private void parseToBeNestedInCatches(String line) {
		Boolean nesting = false;
		if (line.endsWith("{}")) {
			// Superfluous line, there is nothing to be nested in catches.
			return;
		}
		else if (line.endsWith("{")) {
			nesting = true;
    		line = line.substring(0, line.length()-1).trim();
		}
		else {
			// Unrecognized ending, ignore this line.
			return;
		}

		List<TryBlockMapEntry> toBeNestedInCatches = new ArrayList<TryBlockMapEntry>();
		
		if (!stack.isEmpty()) {
			Object parent = stack.peek();
			if (parent instanceof TryBlockMapEntry) {
				stack.push(toBeNestedInCatches);
			}
		}
		// If toBeNestedInCatches has not been pushed on the stack, we'll likely encounter a structure error later on. That is fine for this simple parser.
	}
	
	private void processBlockClosure() {
		while (!stack.isEmpty()) {
			Object parent = stack.peek();
			if (parent instanceof TryBlockMapEntry) {
				// For a TryBlockMapEntry we don't use {}; the block closure is for something else but
				// we do have to close an encountered TryBlockMapEntry on the fly (and then keep going).
				stack.pop();
			}
			else if (parent instanceof List<?>) {
				// The only we thing we put on the stack that is some sort of List is a List<TryBlockMapEntry>, so a 'toBeNestedInCatches'.
				var toBeNestedInCatches = (List<TryBlockMapEntry>)parent;
				stack.pop();
				// Now there should be a TryBlockMapEntry at the top of the stack. We need to add the entries in toBeNestedInCatches to it.
				if (!stack.isEmpty()) {
					parent = stack.peek();
					if (parent instanceof TryBlockMapEntry) {
						for (TryBlockMapEntry toBeNested : toBeNestedInCatches) {
							((TryBlockMapEntry) parent).nestInCatches(toBeNested);
						}
					}
				}
			} else {
				stack.pop();
				break;
			}
		}
	}

    private Integer parseState(String line) {
        if (line.contains("state=?")) {
            return null;
        }
        String[] parts = line.split("\\(state=");
        if (parts.length < 2)
        	return null;
        parts = parts[1].trim().split("\\)");
        return Integer.parseInt(parts[0].trim());
    }

}
