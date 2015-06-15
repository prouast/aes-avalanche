package rijndael;

/**
 * Implementation of a Galois field.
 * @author prouast Pnorth
 */
public class GaloisField {
    
    private final int fieldSize;
    private final int irreduciblePolynomial;
    
    /**
     * Create a new GaloisField instance.
     * @param fieldSize field size
     * @param irreduciblePolynomial irreducible polynomial 
     */
    public GaloisField(int fieldSize, int irreduciblePolynomial) {
        this.fieldSize = fieldSize;
        this.irreduciblePolynomial = irreduciblePolynomial;
    }
    
    /**
     * Galois field division.
     * a/b
     * @param a divident
     * @param b divisor
     * @return result
     */
    public int divide(int a, int b) {
        while (a >= fieldSize) { // Do until size is valid
            // Idea: Shift by appropriate number of bits to the left and XOR
            a = a ^ (b << (Integer.numberOfLeadingZeros(b)-Integer.numberOfLeadingZeros(a)));
        }
        return a;
    }
    
    /**
     * Galois field multiplication.
     * a*b
     * @param a a
     * @param b b
     * @return result
     */
    public int multiply(int a, int b) {
        // Idea: Use a to keep track of how shifted versions of b
        //       have been XORed
        int result = 0;
        while (a != 0) { // Sum partial results based on a
            if (a % 2 == 1) { // Is last bit a one?
                result ^= b; // XOR b with current result
            }
            a >>= 1; // Shift a
            b <<= 1; // Shift b
        }
        // Divide by irreducible polynomial
        result = divide(result, irreduciblePolynomial);
        return result;
    }
}