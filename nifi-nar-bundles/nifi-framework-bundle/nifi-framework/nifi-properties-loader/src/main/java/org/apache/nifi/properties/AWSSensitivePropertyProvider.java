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
package org.apache.nifi.properties;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GenerateRandomResult;
import com.amazonaws.services.kms.model.GenerateRandomRequest;


// Rename to AWSKMS
public class AWSSensitivePropertyProvider implements SensitivePropertyProvider {
    private static final Logger logger = LoggerFactory.getLogger(AWSSensitivePropertyProvider.class);

    private static final String IMPLEMENTATION_NAME = "AWS KMS Sensitive Property Provider";
    private static final String IMPLEMENTATION_KEY = "aws/kms/"; // .protected=aws/kms/some-key-id-goes-here // follow-on ticket for ConfigEncryption toolkit

    private AWSKMS client;
    private final String key;

    public AWSSensitivePropertyProvider(String keyId) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        this.key = validateKey(keyId);
        this.client = AWSKMSClientBuilder.standard().build();
    }

    private String validateKey(String keyId) {
        if (keyId == null || StringUtils.isBlank(keyId)) {
            throw new SensitivePropertyProtectionException("The key cannot be empty");
        }
        return keyId;
    }

    /**
     * Returns the name of the underlying implementation.
     *
     * @return the name of this sensitive property provider
     */
    @Override
    public String getName() {
        return IMPLEMENTATION_NAME;

    }

    /**
     * Returns the key used to identify the provider implementation in {@code nifi.properties}.
     *
     * @return the key to persist in the sibling property
     */
    @Override
    public String getIdentifierKey() {
        return IMPLEMENTATION_KEY + key; // getIdentifierKey() has to include the kms key id/alias/arn
    }
    

    /**
     * Returns the encrypted cipher text.
     *
     * @param unprotectedValue the sensitive value
     * @return the value to persist in the {@code nifi.properties} file
     * @throws SensitivePropertyProtectionException if there is an exception encrypting the value
     */
    @Override
    public String protect(String unprotectedValue) throws SensitivePropertyProtectionException {
        if (unprotectedValue == null || unprotectedValue.trim().length() == 0) {
            throw new IllegalArgumentException("Cannot encrypt an empty value");
        }

        EncryptRequest request = new EncryptRequest()
            .withKeyId(key)
            .withPlaintext(ByteBuffer.wrap(unprotectedValue.getBytes()));

        EncryptResult response = client.encrypt(request);
        return Hex.toHexString(response.getCiphertextBlob().array());
    }

    /**
     * Returns the decrypted plaintext.
     *
     * @param protectedValue the cipher text read from the {@code nifi.properties} file
     * @return the raw value to be used by the application
     * @throws SensitivePropertyProtectionException if there is an error decrypting the cipher text
     */
    @Override
    public String unprotect(String protectedValue) throws SensitivePropertyProtectionException {
        DecryptRequest request = new DecryptRequest()
            .withCiphertextBlob(ByteBuffer.wrap(Hex.decode(protectedValue)));
                                
        DecryptResult response = client.decrypt(request);
        return new String(response.getPlaintext().array());
    }

    public String generateRandom(Integer size) {
        GenerateRandomRequest request = new GenerateRandomRequest()
            .withNumberOfBytes(size);
        
        GenerateRandomResult response = client.generateRandom(request);
        return Hex.toHexString(response.getPlaintext().array());
    }

    public boolean providesScheme(String protectionScheme) throws SensitivePropertyProtectionException {
        return protectionScheme != null && protectionScheme.startsWith(IMPLEMENTATION_KEY);        
    }
    
    public static boolean canHandleScheme(String protectionScheme) throws SensitivePropertyProtectionException {
        return protectionScheme != null && protectionScheme.startsWith(IMPLEMENTATION_KEY);        
    }
    
}
