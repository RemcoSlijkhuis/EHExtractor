package msvc.exceptions.src;

public interface ITryCatch {
	public BlockType getBlockType();
	public int getState();
	public void setState(int state) throws IllegalArgumentException;
	public boolean hasValidState();
	public void nest(TryBlockMapEntry tryBlockMapEntry);
}
