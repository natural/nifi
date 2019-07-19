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

import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;


/**
 *
 */
public class SimpleCipherOutputStream extends CipherOutputStream {
    static final byte MARKER_BYTE = 0x7f;


    public SimpleCipherOutputStream(OutputStream out, AEADBlockCipher cipher) {
        super(out, cipher);
    }

    /**
     *
     * @param out
     * @param key
     * @return
     * @throws IOException
     */
    public static OutputStream wrapWithKey(OutputStream out, SecretKey key) throws IOException {
        if (key == null) {
            return out;
        }

        byte[] iv = SimpleCipherTool.initIV();
        byte[] aad = SimpleCipherTool.initAAD();
        AEADBlockCipher cipher = SimpleCipherTool.initCipher(key, true, iv, aad);

        out.write(MARKER_BYTE);
        out.write(iv);
        out.write(aad);

        return new SimpleCipherOutputStream(out, cipher);
    }
}
