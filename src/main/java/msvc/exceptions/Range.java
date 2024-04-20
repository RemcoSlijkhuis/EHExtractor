package msvc.exceptions;

/**
 * Represents a generic range of comparable objects.
 *
 * <p>This class encapsulates a range with minimum and maximum (inclusive) bounds.
 *
 * @param <T> The type of the Comparable elements in the range.
 */
public class Range<T extends Comparable<T>> {
    private T min;
    private T max;

    /**
     * Creates a new range with the specified minimum and maximum values.
     *
     * @param min The minimum value of the range (inclusive).
     * @param max The maximum value of the range (inclusive).
     */
    public Range(T min, T max) {
        this.min = min;
        this.max = max;
    }
    
    /**
     * Determines whether the specified value falls within the bounds of this range.
     *
     * @param value The value to check.
     * @return true if the value is within the range, false otherwise.
     */
    public boolean contains(T value) {
        return value.compareTo(min) >= 0 && value.compareTo(max) <= 0;
    }
    
    /**
     * Checks if the entire specified range falls within this range.
     *
     * @param other The range to check.
     * @return true if the entire other range is contained within this range, false otherwise.
     */
    public boolean contains(Range<T> other) {
    	return this.contains(other.min) && this.contains(other.max);
    }
        
    /**
     * Generates a hash code for this range.
     *
     * @return The hash code value for this object.
     */
    @Override
    public int hashCode() {
    	return this.min.hashCode() * this.max.hashCode();
    }
    
    /**
     * Compares this range with the specified object for equality.
     *
     * @param obj The object to compare with.
     * @return true if the specified object represents the same range as this one.
     */
    @Override
    public boolean equals(Object obj) {
    	if (obj == null)
    		return false;
    	if (obj == this)
    		return true;
    	if (obj.getClass() != this.getClass())
    		return false;
    	
    	Range<T> other = (Range<T>) obj;
    	return (other.min.equals(this.min) && other.max.equals(this.max));
    }
}
