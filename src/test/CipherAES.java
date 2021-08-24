package test;

import java.nio.charset.Charset;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES 128bit 암호화/복호화
 */
public class CipherAES {

	 // 알고리즘 CBC 타입은 결과가 계속 변경되고 IV값이 필요하기 때문에 ECB로 사용함
    private static final String TRANSFORM = "AES/ECB/PKCS5Padding";
    
    /**
     * 암호화
     * @param plainText 원본 문자열
     * @return 암호화 문자열
     * @throws Exception
     */
    public static String encrypt(String plainText, String decEnckey) throws Exception {    	
        if (null != plainText && plainText.length() > 0) {
            
            // keySpec 생성
        	byte[] raw = decEnckey.getBytes("UTF-8");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            
            // 암호화 모듈 인스턴스 생성 및 초기화
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            
            // 암호화
            byte[] encrypted = cipher.doFinal(plainText.getBytes(Charset.forName("UTF-8")));
            return asHex(encrypted);
        } else {
            return plainText;
        }
    }

    /**
     * 복호화
     * @param cipherText 암호화된 문자열
     * @return 복호화된 문자열
     * @throws Exception
     */
    public static String decrypt(String cipherText, String decEnckey) throws Exception {    	
        if (null != cipherText && cipherText.length() > 0) {

            // keySpac 생성
        	byte[] raw = decEnckey.getBytes("UTF-8");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            
            // 암호화 모듈 인스턴스 생성 및 초기화
            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            
            // 복호화
            byte[] original = cipher.doFinal(fromString(cipherText));
            String originalString = new String(original, Charset.forName("UTF-8"));
            return originalString;
        } else {
            return "";
        }
    }

    /**
     * byte 배열을 Hex 문자열로 반환
     * @param buf byte 배열
     * @return
     */
    private static String asHex(byte buf[]) {
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10)
                strbuf.append("0");

            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }

        return strbuf.toString();
    }

    /*
     * hex 문자열을 byte 배열로 반환
     */
    private static byte[] fromString(String hex) {
        int len = hex.length();
        byte[] buf = new byte[((len + 1) / 2)];

        int i = 0, j = 0;
        if((len & 1) == 1){
            buf[j++] = (byte) fromDigit(hex.charAt(i++));
        }
        while (i < len) {
            buf[j++] = (byte) ((fromDigit(hex.charAt(i++)) << 4) | fromDigit(hex.charAt(i++)));
        }
        return buf;
    }

    /*
     * char를 Hex 번호로 반환
     */
    private static int fromDigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;

        throw new IllegalArgumentException("invalid hex digit '" + ch + "'");
    }
}
