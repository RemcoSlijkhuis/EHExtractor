package msvc.exceptions.src;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerTypeModifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.List;

public class CatchHandlerFactory {

	public List<CatchHandler> getCatchHandlers(EHCatchHandlerModel catchHandlerModel, int nCatches) throws InvalidDataTypeException {
		List<CatchHandler> catchHandlers = new ArrayList<CatchHandler>();
		for (int i=0; i<nCatches; i++) {
			CatchHandler catchHandler = getCatchHandler(catchHandlerModel, i);
			catchHandlers.add(catchHandler);
		}
		return catchHandlers;
	}

	private CatchHandler getCatchHandler(EHCatchHandlerModel catchHandlerModel, int catchHandlerInd) throws InvalidDataTypeException {
		EHCatchHandlerTypeModifier adjectives = catchHandlerModel.getModifiers(catchHandlerInd);
		Address pType = catchHandlerModel.getTypeDescriptorAddress(catchHandlerInd);	// TODO Not really needed.
		Scalar dispCatchObj = catchHandlerModel.getCatchObjectDisplacement(catchHandlerInd);
		Address address = catchHandlerModel.getCatchHandlerAddress(catchHandlerInd);
		TypeDescriptorModel typeDescriptor = catchHandlerModel.getTypeDescriptorModel(catchHandlerInd);
		String handlerName = catchHandlerModel.getCatchHandlerName(catchHandlerInd);

		return new CatchHandler(adjectives, pType, dispCatchObj, address, typeDescriptor, handlerName);
	}

	public CatchHandler createSimpleCatchHandler(String name) {
		EHCatchHandlerTypeModifier adjectives = new EHCatchHandlerTypeModifier(1);
		Address pType = null;
		Scalar dispCatchObj = null;
		Address address = null;
		TypeDescriptorModel typeDescriptorModel = null;
		CatchHandler catchHandler = new CatchHandler(adjectives, pType, dispCatchObj, address, typeDescriptorModel, name);
		return catchHandler;
	}

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
