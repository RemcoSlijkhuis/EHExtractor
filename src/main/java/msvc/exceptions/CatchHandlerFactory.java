package msvc.exceptions;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerTypeModifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.List;

/**
 * Factory class for creating CatchHandler objects (catch blocks).
 */
public class CatchHandlerFactory {

    /**
     * Creates a list of CatchHandler (catch block) instances based on the provided catchHandlerModel
     * and the specified number of catch handlers.
     * 
     * @param catchHandlerModel The EHCatchHandlerModel model containing the catch handler information.
     * @param nCatches The number of catch handlers in catchHandlerModel.
     * @return A list of CatchHandler instances.
     * @throws InvalidDataTypeException if there is an error accessing the data model.
     */
	public List<CatchHandler> getCatchHandlers(EHCatchHandlerModel catchHandlerModel, int nCatches) throws InvalidDataTypeException {
		List<CatchHandler> catchHandlers = new ArrayList<CatchHandler>();
		for (int i=0; i<nCatches; i++) {
			CatchHandler catchHandler = getCatchHandler(catchHandlerModel, i);
			catchHandlers.add(catchHandler);
		}
		return catchHandlers;
	}

    /**
     * Creates a CatchHandler (catch block) instance from the catchHandlerModel for the specified catch handler index.
     * 
     * @param catchHandlerModel The EHCatchHandlerModel model to retrieve catch handler information from.
     * @param catchHandlerInd The index of the specific catch handler to create an instance for.
     * @return A CatchHandler instance.
     * @throws InvalidDataTypeException if there is an error accessing the model data
     */
	private CatchHandler getCatchHandler(EHCatchHandlerModel catchHandlerModel, int catchHandlerInd) throws InvalidDataTypeException {
		EHCatchHandlerTypeModifier adjectives = catchHandlerModel.getModifiers(catchHandlerInd);
		Address pType = catchHandlerModel.getTypeDescriptorAddress(catchHandlerInd);	// TODO Not really needed.
		Scalar dispCatchObj = catchHandlerModel.getCatchObjectDisplacement(catchHandlerInd);
		Address address = catchHandlerModel.getCatchHandlerAddress(catchHandlerInd);
		TypeDescriptorModel typeDescriptor = catchHandlerModel.getTypeDescriptorModel(catchHandlerInd);
		String handlerName = catchHandlerModel.getCatchHandlerName(catchHandlerInd);

		return new CatchHandler(adjectives, pType, dispCatchObj, address, typeDescriptor, handlerName);
	}

    /**
     * Creates a very basic CatchHandler (catch block) instance using only the name.
     * 
     * @param name The name to use in the CatchHandler.
     * @return A CatchHandler instance.
     */
	public CatchHandler createSimpleCatchHandler(String name) {
		EHCatchHandlerTypeModifier adjectives = new EHCatchHandlerTypeModifier(1);
		Address pType = null;
		Scalar dispCatchObj = null;
		Address address = null;
		TypeDescriptorModel typeDescriptorModel = null;
		CatchHandler catchHandler = new CatchHandler(adjectives, pType, dispCatchObj, address, typeDescriptorModel, name);
		return catchHandler;
	}

    /**
     * Creates a basic CatchHandler (catch block) instance using the most useful (and actually used) properties.
     * 
     * @param typeName The name for the exception type the catch block handles.
     * @param state The state of the CatchHandler.
     * @param address The address of the catch block code.
     * @return A CatchHandler instance.
     */
	public CatchHandler createSimpleCatchHandler(String typeName, Integer state, Integer address) {
		EHCatchHandlerTypeModifier adjectives = new EHCatchHandlerTypeModifier(1);
		Address pType = null;
		Scalar dispCatchObj = null;
		//TypeDescriptorModel typeDescriptorModel = null;
		String name = "<some name>";

		var altParams = new CatchHandler.AlternativeParams()
							.withAddress(address)
							.withExceptionType(typeName);
		//CatchHandler catchHandler = new CatchHandler(adjectives, pType, dispCatchObj, address, typeDescriptorModel, name);
		CatchHandler catchHandler = new CatchHandler(adjectives, pType, dispCatchObj, altParams, name);
		
		catchHandler.setState(state);
		return catchHandler;
	}
}
