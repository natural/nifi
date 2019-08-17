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

import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.properties.sensitive.aes.AESSensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.aws.kms.AWSKMSSensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.gcp.kms.GCPKMSSensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.hashicorp.vault.VaultSensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.keystore.KeyStoreSensitivePropertyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class hides the various SPP subclass construction from clients.
 *
 */
public class StandardSensitivePropertyProvider {
    private static final Logger logger = LoggerFactory.getLogger(StandardSensitivePropertyProvider.class);

    /**
     * Creates a {@link SensitivePropertyProvider} suitable for a given key or key id.
     *
     * If an empty or null key/key id is given, this implementation returns null.  This is a convenience
     * for clients using the various Property classes, as those classes allow a null SensitivePropertyProvider.
     *
     * If no provider recognizes a key/key id, this implementation throws {@link SensitivePropertyProtectionException}.
     *
     * @param key provider encryption key
     * @param scheme name of encryption or protection scheme
     * @return concrete instance of SensitivePropertyProvider, or null when no key/key id is specified
     * @throws SensitivePropertyProtectionException when a key/key id is not handled by any provider.
     */
    public static SensitivePropertyProvider fromKey(String key, String scheme) {
        if (StringUtils.isBlank(key)) {
            return null;

        } else if (VaultSensitivePropertyProvider.isProviderFor(key) || VaultSensitivePropertyProvider.isProviderFor(scheme)) {
            logger.debug("StandardSensitivePropertyProvider selected specific Vault provider for key: " + VaultSensitivePropertyProvider.toPrintableString(key));
            return new VaultSensitivePropertyProvider(key);

        } else if (KeyStoreSensitivePropertyProvider.isProviderFor(key) || KeyStoreSensitivePropertyProvider.isProviderFor(scheme)) {
            logger.debug("StandardSensitivePropertyProvider selected specific KeyStore provider for key: " + KeyStoreSensitivePropertyProvider.toPrintableString(key));
            return new KeyStoreSensitivePropertyProvider(key);

        } else if (GCPKMSSensitivePropertyProvider.isProviderFor(key) || GCPKMSSensitivePropertyProvider.isProviderFor(scheme)) {
            logger.debug("StandardSensitivePropertyProvider selected specific GCP KMS provider for key: " + GCPKMSSensitivePropertyProvider.toPrintableString(key));
            return new GCPKMSSensitivePropertyProvider(key);

        } else if (AWSKMSSensitivePropertyProvider.isProviderFor(key) || AWSKMSSensitivePropertyProvider.isProviderFor(scheme)) {
            logger.debug("StandardSensitivePropertyProvider selected specific AWS KMS provider for key: " + AWSKMSSensitivePropertyProvider.toPrintableString(key));
            return new AWSKMSSensitivePropertyProvider(key);

        } else if (AESSensitivePropertyProvider.isProviderFor(scheme) || StringUtils.isEmpty(scheme)) {
            logger.debug("StandardSensitivePropertyProvider selected specific AES provider for key: " + AESSensitivePropertyProvider.toPrintableString(key));
            return new AESSensitivePropertyProvider(key);
        }

        throw new SensitivePropertyProtectionException("No sensitive property provider for key or key id.");
    }

    /**
     * Creates a {@link SensitivePropertyProvider} suitable for a given key or key id, without specifying a protection
     * or encryption scheme.
     *
     * @param key protection or encryption key
     * @return concrete instance of SensitivePropertyProvider, or null when no key/key id is specified
     * @throws SensitivePropertyProtectionException when a key/key id is not handled by any provider.
     */
    public static SensitivePropertyProvider fromKey(String key) {
        return fromKey(key, "");
    }

    /**
     * True if at least one known sensitive property provider implements protect/unprotect for the given scheme.
     *
     * @param scheme name of encryption or protection scheme
     * @return true if at least one provider handles scheme
     */
    public static boolean hasProviderFor(String scheme) {
        return VaultSensitivePropertyProvider.isProviderFor(scheme)
                || KeyStoreSensitivePropertyProvider.isProviderFor(scheme)
                || GCPKMSSensitivePropertyProvider.isProviderFor(scheme)
                || AWSKMSSensitivePropertyProvider.isProviderFor(scheme)
                || AESSensitivePropertyProvider.isProviderFor(scheme);
    }

    /**
     * @return the default protection scheme from the default provider.
     */
    public static String getDefaultProtectionScheme() {
        return AESSensitivePropertyProvider.getDefaultProtectionScheme();
    }
}
