package com.cd.mfa;

import com.google.common.base.Strings;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
public class TotpUtil {

    public String generateSecret(){
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    public static String generateTOTP(String secretKey) {
        long timeStep = 30; // 30 seconds
        long currentTime = System.currentTimeMillis() / 1000;
        long timeIndex = currentTime / timeStep;
        return generateTOTP(secretKey, timeIndex);
    }

    private static String generateTOTP(String secretKey, long timeIndex) {
        try {
            Base32 base32 = new Base32();
            byte[] decodedKey = base32.decode(secretKey);
            byte[] data = new byte[8];
            long value = timeIndex;
            for (int i = 7; value > 0; i--) {
                data[i] = (byte) (value & 0xFF);
                value >>= 8;
            }
            SecretKeySpec signKey = new SecretKeySpec(decodedKey, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0xF;
            int binary = ((hash[offset] & 0x7F) << 24)
                       | ((hash[offset + 1] & 0xFF) << 16)
                       | ((hash[offset + 2] & 0xFF) << 8)
                       | (hash[offset + 3] & 0xFF);
            int otp = binary % 1000000;
            return Strings.padStart(Integer.toString(otp), 6, '0');
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error generating TOTP", e);
        }
    }

    public boolean verifyCode(String secretKey, String userInputOTP) {
        String generatedOTP = generateTOTP(secretKey);
        return generatedOTP.equals(userInputOTP);
    }

    public String getQRCodeURL(String secretKey, String accountName, String issuer) {
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s",
            issuer,
            accountName,
            secretKey,
            issuer
        );
    }
}