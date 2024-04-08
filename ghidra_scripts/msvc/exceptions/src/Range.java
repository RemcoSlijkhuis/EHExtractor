package msvc.exceptions.src;

public class Range<T extends Comparable<T>> {
    private T min;
    private T max;

    public Range(T min, T max) {
        this.min = min;
        this.max = max;
    }
    
    public boolean contains(T value) {
        return value.compareTo(min) >= 0 && value.compareTo(max) <= 0;
    }
    
    public boolean contains(Range<T> other) {
    	return this.contains(other.min) && this.contains(other.max);
    }
        
    @Override
    public int hashCode() {
    	return this.min.hashCode() * this.max.hashCode();
    }
    
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
