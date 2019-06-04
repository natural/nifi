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
package org.apache.nifi.properties.sensitive.aws.kms;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.lang3.StringUtils;
import org.apache.nifi.properties.PropertyMetadata;
import org.apache.nifi.properties.sensitive.SensitivePropertyProtectionException;
import org.apache.nifi.properties.sensitive.SensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.SensitivePropertyProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class AWSKMSSensitivePropertyProviderFactory implements SensitivePropertyProviderFactory {
    private static final Logger logger = LoggerFactory.getLogger(AWSKMSSensitivePropertyProviderFactory.class);

    PropertyMetadata property;

    public AWSKMSSensitivePropertyProviderFactory(PropertyMetadata props) {
        this.property = props;
    }

    public SensitivePropertyProvider getProvider() throws SensitivePropertyProtectionException {
        final String selector = property.getPropertyValue();
        try {
            if (selector != null && !StringUtils.isBlank(selector)) {
                return new AWSKMSSensitivePropertyProvider(selector);
            } else {
                throw new SensitivePropertyProtectionException("The provider factory cannot generate providers without a key");
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            String msg = "Error creating AWS Sensitive Property Provider";
            logger.warn(msg, e);
            throw new SensitivePropertyProtectionException(msg, e);
        }
    }

    @Override
    public String toString() {
        return "SensitivePropertyProviderFactory for creating AWSSensitivePropertyProviders";
    }
    
    public static boolean accepts(PropertyMetadata prop) {
        return false;
    }
}
