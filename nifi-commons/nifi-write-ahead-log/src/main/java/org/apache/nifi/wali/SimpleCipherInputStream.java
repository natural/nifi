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
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;


public class SimpleCipherInputStream extends CipherInputStream {
    // clients need to know the cipher we used so they can size their buffers:
    protected AEADBlockCipher cipher;

    public SimpleCipherInputStream(InputStream input, AEADBlockCipher cipher) {
        super(input, cipher);
        this.cipher = cipher;
    }

    public static SimpleCipherInputStream initWithKey(InputStream in, SecretKey key) throws IOException {
        byte[] iv = new byte[SimpleCipher.IV_BYTE_LEN];

        int len = in.read(iv);
        if (len != iv.length) {
            throw new IOException("f1");
        }

        byte[] aad = new byte[SimpleCipher.AAD_BYTE_LEN];
        len = in.read(aad);
        if (len != aad.length) {
            throw new IOException("f2");
        }

        AEADBlockCipher cipher = SimpleCipher.initCipher(false, key, iv, aad);
        final SimpleCipherInputStream stream = new SimpleCipherInputStream(in, cipher);
        return stream;
    }
}
