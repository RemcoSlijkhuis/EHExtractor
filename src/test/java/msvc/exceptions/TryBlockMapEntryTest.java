package msvc.exceptions;

import static org.junit.Assert.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerTypeModifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.scalar.Scalar;

import msvc.exceptions.*;

/**
 * Unit tests for TryBlockMapEntry. Could be extended to use the resources containing output layouts for more variety.
 */
public class TryBlockMapEntryTest {

	protected TryBlockMapEntry tryBlockMapEntry;

	@Before
	public void setUp() throws Exception {
		int mapIndex = 0;
		int tryLow = 0;
		int tryHigh = 0;
		int catchHigh = 1;
		int nCatches = 1;
		Address pHandlerArray = null;
		List<CatchHandler> catchHandlers = new ArrayList<CatchHandler>();
		
		TryBlock tryBlock = new TryBlock(tryLow, tryHigh);
		CatchHandler catchHandler = createSimpleCatchHandler("Some handler");
		catchHandlers.add(catchHandler);

		tryBlockMapEntry = new TryBlockMapEntry(mapIndex, tryLow, tryHigh, catchHigh, nCatches, pHandlerArray, tryBlock, catchHandlers);
	}
	
	private CatchHandler createSimpleCatchHandler(String name) {
		EHCatchHandlerTypeModifier adjectives = new EHCatchHandlerTypeModifier(1);
		Address pType = null;
		Scalar dispCatchObj = null;
		Address address = null;
		TypeDescriptorModel typeDescriptorModel = null;
		CatchHandler catchHandler = new CatchHandler(adjectives, pType, dispCatchObj, address, typeDescriptorModel, name);
		return catchHandler;
	}

	/*
	@Test
	public void testTryBlockMapEntry() {
		fail("Not yet implemented");
	}
	*/

	@Test
	public void testNestingInTry() {
		assertFalse(tryBlockMapEntry.nestingInTry());
	}

	@Test
	public void testNestingInCatches() {
		assertFalse(tryBlockMapEntry.nestingInCatches());
	}

	@Test
	public void testIsLeaf() {
		assertTrue(tryBlockMapEntry.isLeaf());
	}

	@Test
	public void testIsSingletLeaf() {
		assertTrue(tryBlockMapEntry.isSingletLeaf());
	}

	@Test
	public void testGetStateRangeOk() {
		var range = new Range<Integer>(0, 1);
		assertEquals(range, tryBlockMapEntry.getStateRange());
	}

	@Test
	public void testGetStateRangeWrong() {
		var range = new Range<Integer>(0, 10);
		assertNotEquals(range, tryBlockMapEntry.getStateRange());
	}

	@Test
	public void testGetTryStateRangeOk() {
		var range = new Range<Integer>(0, 0);
		assertEquals(range, tryBlockMapEntry.getTryStateRange());
	}

	@Test
	public void testGetTryStateRangeWrong() {
		var range = new Range<Integer>(0, 10);
		assertNotEquals(range, tryBlockMapEntry.getTryStateRange());
	}

	@Test
	public void testGetNestedInTryEmpty() {
		assertEquals(0, tryBlockMapEntry.getNestedInTry().size());
	}

// This unit test will become useful when more complex structures are introduced using the output layout resources.
//	@Test
//	public void testGetNestedInTry() {
//		fail("Not yet implemented");
//	}

	@Test
	public void testGetNestedInCatchesEmpty() {
		assertEquals(0, tryBlockMapEntry.getNestedInCatches().size());
	}

// This unit test will become useful when more complex structures are introduced using the output layout resources.
//	@Test
//	public void testGetNestedInCatches() {
//		fail("Not yet implemented");
//	}

// Current nestInTry method is intended for constructing based on existing structures and not for constructing new structures from scratch.
// As such, the only thing that currently happens in nestInTry is adding an object to a list. This is not very useful to unit test.
//	@Test
//	public void testNestInTry() {
//		fail("Not yet implemented");
//	}

// Current nestInCatches method is intended for constructing based on existing structures and not for constructing new structures from scratch.
// As such, the only thing that currently happens in nestInCatches is adding an object to a list. This is not very useful to unit test.
//	@Test
//	public void testNestInCatches() {
//		fail("Not yet implemented");
//	}

	@Test
	public void testGetTryBlock() {
		var tryBlock = tryBlockMapEntry.getTryBlock();
		assertEquals(0, tryBlock.getTryLow());
		assertEquals(0, tryBlock.getTryHigh());
		assertEquals(0, tryBlock.getState());
	}

	@Test
	public void testGetCatchHandlers() {
		var catchHandlers = tryBlockMapEntry.getCatchHandlers();
		assertEquals(1, catchHandlers.size());

		var catchHandler = catchHandlers.get(0);
		assertEquals(0, catchHandler.getNested().size());
		assertFalse(catchHandler.hasValidState());
	}

	/*
	@Test
	public void testGetMapIndex() {
		assertEquals(0, tryBlockMapEntry.getMapIndex());
	}

	@Test
	public void testGetTryLow() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetTryHigh() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetCatchHigh() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetNCatches() {
		fail("Not yet implemented");
	}
	*/

}
