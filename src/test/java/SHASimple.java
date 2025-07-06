import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

public class SHASimple {

    private MessageDigest sha;

    public boolean setUp() throws NoSuchAlgorithmException {
        // Try to get the SUN provider's SHA implementation
        sha = MessageDigest.getInstance("SHA");
        
        // Verify we're using the SUN provider
        String provider = sha.getProvider().getName();
        return "SUN".equals(provider);
    }

    public boolean testEmptyString() {
        // Known SHA-1 hash of empty string
        byte[] expected = hexStringToByteArray("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        byte[] actual = sha.digest();
        System.out.println("empty expected: "+ bytesToHexString(expected));
        System.out.println("empty actual: "+ bytesToHexString(actual));
        boolean res = bytesToHexString(actual).equals(bytesToHexString(expected));
        System.out.println("result: " + res);
        return res;
    }

    public boolean testSimpleString() {
        // Known SHA-1 hash of "abc"
        byte[] expected = hexStringToByteArray("a9993e364706816aba3e25717850c26c9cd0d89d");
        byte[] actual = sha.digest("abc".getBytes());
        System.out.println("simple expected: "+ bytesToHexString(expected));
        System.out.println("simple actual: "+ bytesToHexString(actual));
        boolean res = bytesToHexString(actual).equals(bytesToHexString(expected));
        System.out.println("result: " + res);
        return res;
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

    public static String bytesToHexString(byte[] bytes) {
      StringBuilder hexString = new StringBuilder();
      for (byte b : bytes) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) {
          hexString.append('0');
        }
        hexString.append(hex);
      }
      return hexString.toString();
    }

    public static void main(String[] Args) {
        SHASimple S = new SHASimple();
        try {
          if (!S.setUp()) {
            System.out.println("Setup failed");
            return;
          }
          
        } catch(Throwable t) {
          return;
        }
        if (!S.testEmptyString()) {
          System.out.println("Empty failed");          
          return;
        }
        if (!S.testSimpleString()) {
          System.out.println("Empty failed");          
          return;
        }
    }
}
