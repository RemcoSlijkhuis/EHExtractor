package msvc.exceptions;

/**
 * Defines the common functions for the try and catch blocks as implemented in EHExtractor.
 */
public interface ITryCatch {

	/**
     * Returns the type of the block; it can be either TRY (a try block) or CATCH (a catch block).
     * 
     * @return The block type (TRY or CATCH).
     */
	public BlockType getBlockType();

	/**
     * Retrieves the state of the block.
     * 
     * @return the state of the block.
     */
	public int getState();
	
	/**
     * Sets the state of the block.
     * 
     * @param state the state of the block.
     * @throws IllegalArgumentException if the provided state is invalid.
     */
	public void setState(int state) throws IllegalArgumentException;
	
	/**
     * Checks if the state of the block is valid.
     * 
     * @return true if the state is valid, false otherwise.
     */
	public boolean hasValidState();
	
	/**
     * Adds a nested TryBlockMapEntry to the block.
     * 
     * @param tryBlockMapEntry the TryBlockMapEntry to nest within this block.
     */
	public void nest(TryBlockMapEntry tryBlockMapEntry);
}
