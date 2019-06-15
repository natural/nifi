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
package org.apache.nifi.properties.sensitive;

import org.apache.nifi.properties.sensitive.aes.AESSensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.aws.kms.AWSKMSSensitivePropertyProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


/**
 * This class is all that's needed by SP clients.
 *
 */
public class SensitiveProperty implements SensitivePropertyProvider {
    private static final Logger logger = LoggerFactory.getLogger(SensitiveProperty.class);

    public static SensitivePropertyProvider fromKeyAndScheme(String key, String scheme)  {
        logger.info("SensitiveProperty from key: " + key + " scheme: " + scheme);
        return new SensitiveProperty(new AESSensitivePropertyProvider(key));
    }

    // when we don't know what it is:
    public static SensitivePropertyProvider fromAnyValue(String any) throws SensitivePropertyProtectionException {
        // this is where the switching goes
        logger.info("SensitiveProperty from any value: " + any);
        return new SensitiveProperty(new AESSensitivePropertyProvider(any));
    }

    // when we know it's hex:
    public static SensitivePropertyProvider fromHex(String hex) {
        logger.info("SensitiveProperty from hex: " + hex);
        return new SensitiveProperty(new AESSensitivePropertyProvider(hex));
    }

    // when we know it's aws/kms/ or aes/gcm/ etc..
    public static SensitivePropertyProvider fromId(String id) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        logger.info("SensitiveProperty from key id: " + id);
        return new SensitiveProperty(new AWSKMSSensitivePropertyProvider(id));
    }

    private SensitivePropertyProvider provider;

    private SensitiveProperty(SensitivePropertyProvider provider) {
        this.provider = provider;
    }

    /**
     * Returns the name of the underlying implementation.
     *
     * @return the name of this sensitive property provider
     */
    @Override
    public String getName() {
        return provider.getName();
    }

    /**
     * Returns the key used to identify the provider implementation in {@code nifi.properties}.
     *
     * @return the key to persist in the sibling property
     */
    @Override
    public String getIdentifierKey() {
        return provider.getIdentifierKey();
    }

    /**
     * Returns the "protected" form of this value. This is a form which can safely be persisted in the {@code nifi.properties} file without compromising the value.
     * An encryption-based provider would return a cipher text, while a remote-lookup provider could return a unique ID to retrieve the secured value.
     *
     * @param unprotectedValue the sensitive value
     * @return the value to persist in the {@code nifi.properties} file
     */
    @Override
    public String protect(String unprotectedValue) throws SensitivePropertyProtectionException {
        return provider.protect(unprotectedValue);
    }

    /**
     * Returns the "protected" form of this value. This is a form which can safely be persisted in the {@code nifi.properties} file without compromising the value.
     * An encryption-based provider would return a cipher text, while a remote-lookup provider could return a unique ID to retrieve the secured value.
     *
     * @param unprotectedValue the sensitive value
     * @param metadata         per-value metadata necessary to perform the protection
     * @return the value to persist in the {@code nifi.properties} file
     */
    @Override
    public String protect(String unprotectedValue, SensitivePropertyMetadata metadata) throws SensitivePropertyProtectionException {
        return provider.protect(unprotectedValue, metadata);
    }

    /**
     * Returns the "unprotected" form of this value. This is the raw sensitive value which is used by the application logic.
     * An encryption-based provider would decrypt a cipher text and return the plaintext, while a remote-lookup provider could retrieve the secured value.
     *
     * @param protectedValue the protected value read from the {@code nifi.properties} file
     * @return the raw value to be used by the application
     */
    @Override
    public String unprotect(String protectedValue) throws SensitivePropertyProtectionException {
        return provider.unprotect(protectedValue);
    }

    /**
     * Returns the "unprotected" form of this value. This is the raw sensitive value which is used by the application logic.
     * An encryption-based provider would decrypt a cipher text and return the plaintext, while a remote-lookup provider could retrieve the secured value.
     *
     * @param protectedValue the protected value read from the {@code nifi.properties} file
     * @param metadata       per-value metadata necessary to perform the unprotection
     * @return the raw value to be used by the application
     */
    @Override
    public String unprotect(String protectedValue, SensitivePropertyMetadata metadata) throws SensitivePropertyProtectionException {
        return provider.unprotect(protectedValue, metadata);
    }
}
