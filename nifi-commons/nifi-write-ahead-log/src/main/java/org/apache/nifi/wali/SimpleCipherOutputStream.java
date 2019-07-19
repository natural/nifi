/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.wali;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;


class SimpleCipher {
    static final int IV_BYTE_LEN = 20;
    static final int AAD_BYTE_LEN = 32;
    static final int MAC_BIT_LEN = 128;
    static SecureRandom random = new SecureRandom();

    /**
     *
     * @param encrypt
     * @param key
     * @param iv
     * @param aad
     * @return
     */
    static AEADBlockCipher initCipher(boolean encrypt, SecretKey key, byte[] iv, byte[] aad) {
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

public class SimpleCipherOutputStream extends CipherOutputStream {
    public SimpleCipherOutputStream(OutputStream out, AEADBlockCipher cipher) {
        super(out, cipher);
    }

    public static OutputStream initWithKey(OutputStream out, SecretKey key) throws IOException {
        byte[] iv = SimpleCipher.initIV();
        byte[] aad = SimpleCipher.initAAD();
        AEADBlockCipher cipher = SimpleCipher.initCipher(true, key, iv, aad);
        out.write(iv);
        out.write(aad);
        return new SimpleCipherOutputStream(out, cipher);
    }
}
