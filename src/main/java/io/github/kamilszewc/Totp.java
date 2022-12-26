package io.github.kamilszewc;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

/**
 * Time-based One Time Password generator class
 */
public class Totp {

    /**
     * Available hash functions
     */
    public enum HashFunction {HMACSHA1, HMACSHA256, HMACSHA512};

    /**
     * Returns totp code
     * @param secret secret password
     * @return totp code
     * @throws NoSuchAlgorithmException if unsupported hashing algorithm is used
     * @throws InvalidKeyException if wrong key (secret) is used
     */
    public static String getCode(String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        return getCode(secret, 0, 30, getCurrentTimeStamp(), 6, HashFunction.HMACSHA1);
    }

    /**
     * Returns totp code
     * @param secret secret password
     * @param timeStamp time stamp (Unix time)
     * @return totp code
     * @throws NoSuchAlgorithmException if unsupported hashing algorithm is used
     * @throws InvalidKeyException if wrong key (secret) is used
     */
    public static String getCode(String secret, long timeStamp) throws NoSuchAlgorithmException, InvalidKeyException {
        return getCode(secret, 0, 30, timeStamp, 6, HashFunction.HMACSHA1);
    }

    /**
     * Returns totp code
     * @param secret secret password
     * @param hashFunction hash function
     * @return totp code
     * @throws NoSuchAlgorithmException if unsupported hashing algorithm is used
     * @throws InvalidKeyException if wrong key (secret) is used
     */
    public static String getCode(String secret, HashFunction hashFunction) throws NoSuchAlgorithmException, InvalidKeyException {
        return getCode(secret, 0, 30, getCurrentTimeStamp(), 6, hashFunction);
    }

    /**
     * Returns totp code
     * @param secret secret password
     * @param codeLength length of returned code
     * @param hashFunction hash function
     * @return totp code
     * @throws NoSuchAlgorithmException if unsupported hashing algorithm is used
     * @throws InvalidKeyException if wrong key (secret) is used
     */
    public static String getCode(String secret, int codeLength, HashFunction hashFunction) throws NoSuchAlgorithmException, InvalidKeyException {
        return getCode(secret, 0, 30, getCurrentTimeStamp(), codeLength, hashFunction);
    }

    /**
     * Returns totp code
     * @param secret secret password
     * @param epoch epoch
     * @param timeStep length of password validity (in seconds)
     * @param timeStamp time stamp (Unix time)
     * @param codeLength length of returned code
     * @param hashFunction hash function
     * @return totp code
     * @throws NoSuchAlgorithmException if unsupported hashing algorithm is used
     * @throws InvalidKeyException if wrong key (secret) is used
     */
    public static String getCode(
            String secret,
            long epoch,
            int timeStep,
            long timeStamp,
            int codeLength,
            HashFunction hashFunction) throws NoSuchAlgorithmException, IllegalArgumentException, InvalidKeyException {

        long interval = Math.floorDiv(timeStamp - epoch, timeStep);
        byte[] challenge = ByteBuffer.allocate(8).putLong(interval).array();

        Base32 base32 = new Base32();
        byte[] decodedSecret = base32.decode(secret);

        return calculateHotp(decodedSecret, challenge, codeLength, hashFunction);
    }

    /**
     * Returns the remaining code validity time (for 30 sec validity)
     * @return current code remaining validity time
     */
    public static long getCodeRemainingValidityTime() {
        return getCodeRemainingValidityTime(0, 30, getCurrentTimeStamp());
    }

    /**
     * Returns the remaining code validity time
     * @param epoch epoch
     * @param timeStep length of password validity (in seconds)
     * @param timeStamp time stamp (Unix time)
     * @return current code remaining validity time
     */
    public static long getCodeRemainingValidityTime(long epoch, int timeStep, long timeStamp) {
        return (timeStamp - epoch) % timeStep;
    }

    private static String calculateHotp(
            byte[] decodedSecret,
            byte[] challenge,
            int codeLength,
            HashFunction hashFunction) throws NoSuchAlgorithmException, IllegalArgumentException, InvalidKeyException {

        if (!(1 <= codeLength && codeLength <= 9)) throw new IllegalArgumentException("Wrong number of digits");

        SecretKeySpec signKey = new SecretKeySpec(decodedSecret, hashFunction.toString());
        Mac mac = Mac.getInstance(hashFunction.toString());
        mac.init(signKey);
        byte[] hash = mac.doFinal(challenge);

        int offset = hash[hash.length - 1] & 0xf;

        int binary =  ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int code = binary % (int) Math.pow(10, codeLength);

        return String.format("%0" + codeLength + "d", code);
    }

    private static long getCurrentTimeStamp() {
        Calendar calendar = GregorianCalendar.getInstance(TimeZone.getTimeZone("UTC"));
        return calendar.getTimeInMillis() / 1000;
    }

}