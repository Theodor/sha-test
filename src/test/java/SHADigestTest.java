import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

public class SHADigestTest {

    private MessageDigest sha;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        // Try to get the SUN provider's SHA implementation
        sha = MessageDigest.getInstance("SHA");
        
        // Verify we're using the SUN provider
        String provider = sha.getProvider().getName();
        assertTrue("Test requires SUN provider", "SUN".equals(provider));
    }

    @Test
    public void testEmptyString() {
        // Known SHA-1 hash of empty string
        byte[] expected = hexStringToByteArray("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        byte[] actual = sha.digest();
        assertArrayEquals("Empty string hash mismatch", expected, actual);
    }

    @Test
    public void testSimpleString() {
        // Known SHA-1 hash of "abc"
        byte[] expected = hexStringToByteArray("a9993e364706816aba3e25717850c26c9cd0d89d");
        byte[] actual = sha.digest("abc".getBytes());
        assertArrayEquals("Simple string hash mismatch", expected, actual);
    }

    @Test
    public void testLongString() {
        // Known SHA-1 hash of 1,000,000 repetitions of 'a'
        byte[] expected = hexStringToByteArray("34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        
        // Create a 1,000,000 byte array of 'a's (more efficient than string repetition)
        byte[] input = new byte[1000000];
        Arrays.fill(input, (byte)'a');
        
        byte[] actual = sha.digest(input);
        assertArrayEquals("Long string hash mismatch", expected, actual);
    }

    @Test
    public void testChunkedUpdate() {
        // Known SHA-1 hash of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        byte[] expected = hexStringToByteArray("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        
        String testString = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        
        // Update in chunks to test partial updates
        sha.update(testString.substring(0, 10).getBytes());
        sha.update(testString.substring(10, 20).getBytes());
        sha.update(testString.substring(20).getBytes());
        
        byte[] actual = sha.digest();
        assertArrayEquals("Chunked update hash mismatch", expected, actual);
    }

    @Test
    public void testReset() {
        byte[] firstHash = sha.digest("test".getBytes());
        
        // Reset and digest again - should get same result
        sha.reset();
        byte[] secondHash = sha.digest("test".getBytes());
        assertArrayEquals("Reset failed to produce same hash", firstHash, secondHash);
        
        // Now test with different input
        sha.reset();
        byte[] differentHash = sha.digest("different".getBytes());
        assertFalse("Different input produced same hash", Arrays.equals(firstHash, differentHash));
    }

    @Test
    public void testAlgorithmName() {
        assertEquals("SHA", sha.getAlgorithm());
    }

    @Test
    public void testDigestLength() {
        assertEquals("SHA-1 should produce 20-byte hashes", 20, sha.getDigestLength());
    }

    // Helper method to convert hex string to byte array
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
