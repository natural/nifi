package org.apache.nifi.wali;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
import java.security.SecureRandom;

class SimpleCipherTool {
    static final int IV_BYTE_LEN = 20;
    static final int AAD_BYTE_LEN = 32;
    static final int MAC_BIT_LEN = 128;
    static SecureRandom random = new SecureRandom();

    /**
     *
     * @param key
     * @param encrypt
     * @param iv
     * @param aad
     * @return
     */
    static AEADBlockCipher initCipher(SecretKey key, boolean encrypt, byte[] iv, byte[] aad) {
        if (key == null) {
            return null;
        }
        final AEADParameters param = new AEADParameters(new KeyParameter(key.getEncoded()), MAC_BIT_LEN, iv, aad);
        AEADBlockCipher cipher = new EAXBlockCipher(new AESEngine());
        cipher.init(encrypt, param);
        return cipher;
    }

    /**
     *
     * @return
     */
    static byte[] initIV() {
        return randomBytes(IV_BYTE_LEN);
    }

    /**
     *
     * @return
     */
    static byte[] initAAD() {
        return randomBytes(AAD_BYTE_LEN);
    }

    /**
     *
     * @param size
     * @return
     */
    static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        random.nextBytes(bytes);
        return bytes;
    }
}
