package msvc.exceptions;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.exceptionhandling.EHCatchHandlerTypeModifier;
import ghidra.program.model.address.Address;
import ghidra.program.model.scalar.Scalar;

import msvc.exceptions.*;

/**
 * Unit tests for CatchHandler. Could be extended to use the resources containing output layouts for more variety.
 */
public class CatchHandlerTest {

	protected CatchHandler catchHandler;
	
	@Before
	public void setUp() {
		EHCatchHandlerTypeModifier adjectives = new EHCatchHandlerTypeModifier(1);
		Address pType = null;
		Scalar dispCatchObj = null;
		Address address = null;
		TypeDescriptorModel typeDescriptorModel = null;
		catchHandler = new CatchHandler(adjectives, pType, dispCatchObj, address, typeDescriptorModel, "Some handler");
	}

	/*
	@Test
	public void testCatchHandler() {
		fail("Not yet implemented");
	}
	*/

	@Test
	public void testGetBlockType() {
		assertEquals(BlockType.CATCH, catchHandler.getBlockType());
	}

	@Test
	public void testGetStateAfterBeingSet() {
		catchHandler.setState(10);
		assertEquals(10, catchHandler.getState());
	}

	@Test
	public void testGetStateAfterInit() {
		// TODO This is an implementation detail... 
		assertEquals(-2, catchHandler.getState());
	}

	@Test
	public void testSetState() {
		catchHandler.setState(10);
		assertTrue(catchHandler.hasValidState());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetStateException1() {
		catchHandler.setState(-2);
	}
	
	@Test
	public void testHasValidStateOnInit() {
		assertFalse(catchHandler.hasValidState());
	}

	@Test
	public void testHasValidStateAfterbeingSet() {
		catchHandler.setState(2);
		assertTrue(catchHandler.hasValidState());
	}

	@Test
	public void testNestSizeOk() {
		int tryLow = 0;
		int tryHigh = 10;
		var tryBlock = new TryBlock(tryLow, tryHigh);
		
		TryBlockMapEntry tryBlockMapEntry = new TryBlockMapEntry(1, 2, 3, 4, 5, null, tryBlock, null);
		catchHandler.nest(tryBlockMapEntry);
		assertEquals(1, catchHandler.getNested().size());

		catchHandler.nest(tryBlockMapEntry);
		assertEquals(2, catchHandler.getNested().size());
	}

	/*
	@Test
	public void testGetNested() {
		fail("Not yet implemented");
	}
	*/

	@Test
	public void testNestedEmpty() {
		assertEquals(0, catchHandler.getNested().size());
	}

	/*
	@Test
	public void testGetAddress() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetTypeName() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetInfoLines() {
		fail("Not yet implemented");
	}
	*/

}
