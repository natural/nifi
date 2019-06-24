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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class hides the various SPP subclass construction from clients.
 *
 */
public class StandardSensitivePropertyProvider {
    private static final Logger logger = LoggerFactory.getLogger(StandardSensitivePropertyProvider.class);

    /**
     * Creates a {@link SensitivePropertyProvider} suitable for a given key.
     *
     * If no provider recognizes a key, this implementation still returns an {@link AESSensitivePropertyProvider} with
     * the supplied key.
     *
     * @param keyOrKeyId provider encryption key
     * @param options array of string options
     * @return concrete instance of SensitivePropertyProvider
     */
    public static SensitivePropertyProvider fromKey(String keyOrKeyId, String... options) {
        if (StringUtils.isEmpty(keyOrKeyId)) {
            return null;
        }

        String scheme = "";
        if (options.length > 0) {
            scheme = options[0];
        }

        if (AWSKMSSensitivePropertyProvider.isProviderFor(keyOrKeyId, options)) {
            logger.debug("StandardSensitivePropertyProvider selected specific AWS KMS for key: " + keyOrKeyId + " scheme: " + scheme);
            return new AWSKMSSensitivePropertyProvider(keyOrKeyId);

        } else if (AESSensitivePropertyProvider.isProviderFor(keyOrKeyId, options)) {
            logger.debug("StandardSensitivePropertyProvider selected specific AES provider for key: " + keyOrKeyId + " scheme: " + scheme);
            return new AESSensitivePropertyProvider(keyOrKeyId);

        } else {
            logger.debug("StandardSensitivePropertyProvider selected default (AES) for key: " + keyOrKeyId + " scheme: " + scheme);
            return new AESSensitivePropertyProvider(keyOrKeyId);
        }
    }

    /**
     * @return the default protection scheme from the default provider.
     */
    static String getDefaultProtectionScheme() {
        return AESSensitivePropertyProvider.getDefaultProtectionScheme();
    }
}
