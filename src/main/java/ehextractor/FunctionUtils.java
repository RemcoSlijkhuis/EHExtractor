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

public class FunctionUtils {

	public static Function findFunction(Program program, String partialName, String partialParentNamespace, boolean dereferenceThunks) {
		var logger = Logger.getLogger("EHExtractor");
		
		partialName = partialName.toLowerCase();
		boolean checkParentNamespace = partialParentNamespace != null && !partialParentNamespace.isBlank();
	    if (checkParentNamespace) {
	        partialParentNamespace = partialParentNamespace.toLowerCase();
	    }
	    
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

                if (function.isThunk() && dereferenceThunks) {
                	//println("  Thunk: " + function.getName() + " @ " + function.getEntryPoint());
                	function = function.getThunkedFunction(true);
                	//println("  Thunked function: " + function.getName() + " @ " + function.getEntryPoint());
                }

            	if (!function.getName().toLowerCase().contains(partialName))
            		continue;

            	if (checkParentNamespace && !function.getParentNamespace().getName().toLowerCase().contains(partialParentNamespace))
            		continue;

            	if (!functionsByName.contains(function) ) {
                	functionsByName.add(function);
            	}
            }
            else if (symbol.getSymbolType() == SymbolType.LABEL &&  symbol.getName().toLowerCase().contains(partialName)) {
            	//println("  SYMBOL FOUND! " + symbol.getName());
            	//println("  --SymbolType: " + symbol.getSymbolType());
            	//println("  --Address: " + symbol.getAddress());
            	
            	Function function = functionManager.getFunctionAt(symbol.getAddress());
                if (function == null)
                	continue;

                //println("  --Function: " + function.getName());
            	//println("  --Function.isThunk(): " + function.isThunk());
            	//println("  --Function.getParentNamespace(): " + function.getParentNamespace());            	

                if (function.isThunk() && dereferenceThunks) {
                	//println("    xThunk: " + function.getName() + " @ " + function.getEntryPoint());
                	function = function.getThunkedFunction(true);
                	//println("    xThunked function: " + function.getName() + " @ " + function.getEntryPoint());
                }

            	if (checkParentNamespace && !function.getParentNamespace().getName().toLowerCase().contains(partialParentNamespace))
            		continue;

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
