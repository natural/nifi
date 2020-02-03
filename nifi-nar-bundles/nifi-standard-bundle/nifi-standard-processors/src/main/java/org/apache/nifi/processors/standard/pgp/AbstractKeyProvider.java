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
package org.apache.nifi.processors.standard.pgp;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

class AbstractKeyProvider implements KeyProvider {
    PGPPublicKey publicKey;
    PGPSecretKey secretKey;
    PGPPrivateKey privateKey;

    void init(PGPPublicKey publicKey, PGPSecretKey secretKey, PGPPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
        this.privateKey = privateKey;
    }

    @Override
    public PGPPublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public PGPSecretKey getSecretKey() {
        return secretKey;
    }

    @Override
    public PGPPrivateKey getPrivateKey() {
        return privateKey;
    }
}
