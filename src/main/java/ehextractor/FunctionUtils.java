package ehextractor;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/**
 * Utility class for finding functions within a given program using the Ghidra API.
 */
public class FunctionUtils {

	/**
     * Searches for a function in the given program based on a (possibly partial) name and optionally a (partial) namespace. If needed, thunks can be dereferenced.
     * Tries to account for different ways a function may be known in Ghidra (by name or by label) and for multiple matches.
	 *
     * @param program The program in which to search for the function.
     * @param partialName The name (or part of it) of the function to find.
     * @param partialParentNamespace The namespace (or part of it) of the function to find.
     * @param dereferenceThunks If true, thunks are dereferenced to their primary functions.
     * @return The matching function, or null if no matching function is found.
     */
	public static Function findFunction(Program program, String partialName, String partialParentNamespace, boolean dereferenceThunks) {
		var logger = Logger.getLogger("EHExtractor");
		
		// Set up the (partial) namespace string to be matched (if specified).
		partialName = partialName.toLowerCase();
		boolean checkParentNamespace = partialParentNamespace != null && !partialParentNamespace.isBlank();
	    if (checkParentNamespace) {
	        partialParentNamespace = partialParentNamespace.toLowerCase();
	    }
	    
	    // Loop over all symbols, looking for functions matching the name and namespace criteria.
        FunctionManager functionManager = program.getFunctionManager();
		SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

        var functionsByName = new ArrayList<Function>();
        var functionsByLabel = new ArrayList<Function>();
        
        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();

            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                // Get an actual Function object for this symbol.
                Function function = functionManager.getFunctionAt(symbol.getAddress());
                if (function == null)
                	continue;

                // Dereference the found function if needed.
                if (function.isThunk() && dereferenceThunks) {
                	function = function.getThunkedFunction(true);
                }

                // Name ok?
            	if (!function.getName().toLowerCase().contains(partialName))
            		continue;

            	// Namespace ok?
            	if (checkParentNamespace && !function.getParentNamespace().getName().toLowerCase().contains(partialParentNamespace))
            		continue;

            	// Found a function, matching by name. Add it to the list if not yet seen.
            	if (!functionsByName.contains(function) ) {
                	functionsByName.add(function);
            	}
            }
            else if (symbol.getSymbolType() == SymbolType.LABEL &&  symbol.getName().toLowerCase().contains(partialName)) {
            	// Symbol found, matching the requested (partial) name.

            	// Is there an actual (known) function at that symbol's address?
            	Function function = functionManager.getFunctionAt(symbol.getAddress());
                if (function == null) {
                	// No function here, let's continue looking.
                	continue;                	
                }
                
                // Deference the found function, if needed.
                if (function.isThunk() && dereferenceThunks) {
                	function = function.getThunkedFunction(true);
                }

                // Namespace ok?
            	if (checkParentNamespace && !function.getParentNamespace().getName().toLowerCase().contains(partialParentNamespace))
            		continue;

            	// Found a function, matching by label. Add it to the list if not yet seen.
            	if (!functionsByLabel.contains(function) ) {
                	functionsByLabel.add(function);
            	}
            }            	
        }

        // Log some details about the found functions.
    	if (logger != null) {
            if (functionsByName.size() == 0) {
            	logger.log(Level.FINER, "  No functions found that match by name.");
            }
            else {
            	logger.log(Level.FINER, "  Functions found that match by name:");
                for (Function function : functionsByName) {
                	logger.log(Level.FINER, "    " + function + " @ " + function.getEntryPoint());
                }
            }

            if (functionsByLabel.size() == 0) {
            	logger.log(Level.FINER, "  No functions found that match by label.");
            }
            else {
            	logger.log(Level.FINER, "  Functions found that match by label:");
                for (Function function : functionsByLabel) {
                	logger.log(Level.FINER, "    " + function + " @ " + function.getEntryPoint());
                }
            }
    	}

    	// Return the best matching function.
        if (functionsByName.size() == 1) {
        	Function function = functionsByName.get(0);
        	if (logger != null)
        		logger.log(Level.FINER, "  Returning the 1 function that matched by name: " + function.getName());
        	return function;
        }
        else if (functionsByName.size() == 0 && functionsByLabel.size() == 1) {
        	Function function = functionsByLabel.get(0);
        	if (logger != null)
        		logger.log(Level.FINER, "  Returning the 1 function that matched by label (in the absence of a function matching by name): " + function.getName());
        	return function;
        }
        else if (functionsByName.size() > 0) {
        	Function function = functionsByName.get(0);
        	if (logger != null)
        		logger.log(Level.FINER, "  Returning the first function that matched by name: " + function.getName());
        	return function;
        }
        else if (functionsByLabel.size() > 0) {
        	Function function = functionsByLabel.get(0);
        	if (logger != null)
        		logger.log(Level.FINER, "  Returning the first function that matched by label (in the absence of functions matching by name): " + function.getName());
        	return function;
        }
        else {
        	if (logger != null)
        		logger.log(Level.FINER, "No matching function found.");
        }
        
        return null;
	}

	/**
     * Retrieves all internal functions of the given program.
     * @param program The program from which to retrieve all interal functions.
     * @return A list of all internal functions of the given program.
     */
	public static List<Function> getInternalFunctions(Program program) {
        FunctionManager functionManager = program.getFunctionManager();

    	List<Function> allFuncs = new ArrayList<Function>();
    	SymbolTable symtab = program.getSymbolTable();
    	SymbolIterator si = symtab.getSymbolIterator();
    	while (si.hasNext()) {
    		Symbol s = si.next();
    		if (s.getSymbolType() != SymbolType.FUNCTION || s.isExternal()) {
    			continue;
    		}
    		Function func = functionManager.getFunctionAt(s.getAddress());
    		allFuncs.add(func);
    	}
   		return allFuncs;
	}

}
