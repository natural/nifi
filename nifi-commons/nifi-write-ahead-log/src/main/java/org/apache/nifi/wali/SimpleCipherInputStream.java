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

import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;

/**
 *
 */
public class SimpleCipherInputStream extends CipherInputStream {
    protected AEADBlockCipher cipher;

    /**
     *
     * @param in
     * @param cipher
     */
    public SimpleCipherInputStream(InputStream in, AEADBlockCipher cipher) {
        super(in, cipher);
        this.cipher = cipher;
    }

    /**
     *
     * @param in
     * @param key
     * @return
     * @throws IOException
     */
    public static InputStream wrapWithKey(InputStream in, SecretKey key) throws IOException {
        if (key == null ) {
            return in;
        }

        if (in.markSupported()) {
            in.mark(0);
        }

        try {
            final int marker = in.read();
            if (marker != SimpleCipher.MARKER_BYTE) {
                if (in.markSupported()) {
                    in.reset();
                }
                return in;
            }

            byte[] iv = new byte[SimpleCipher.IV_BYTE_LEN];

            int len = in.read(iv);
            if (len != iv.length) {
                throw new IOException("Could not read IV.");
            }

            byte[] aad = new byte[SimpleCipher.AAD_BYTE_LEN];
            len = in.read(aad);
            if (len != aad.length) {
                throw new IOException("Could not read AAD.");
            }

            AEADBlockCipher cipher = SimpleCipher.initCipher(key, false, iv, aad);
            return new SimpleCipherInputStream(in, cipher);

        } catch (final IOException ignored) {
            if (in.markSupported()) {
                in.reset();
            }
            return in;
        }


    }

    @Override
    public void close() throws IOException {
        try {
            in.close();
        } catch (final Exception ignored) {
            throw new IOException(ignored);
        }
    }
}
