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

import java.lang.reflect.InvocationTargetException;
import org.apache.nifi.properties.PropertyMetadata;
import org.apache.nifi.properties.sensitive.SensitivePropertyProtectionException;
import org.apache.nifi.properties.sensitive.SensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.SensitivePropertyProviderFactory;
import org.apache.nifi.properties.sensitive.aes.AESSensitivePropertyProviderFactory;
import org.apache.nifi.properties.sensitive.aws.kms.AWSKMSSensitivePropertyProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;


public class SensitivePropertyProviderFactorySelector {
    private static final Logger logger = LoggerFactory.getLogger(SensitivePropertyProviderFactorySelector.class);
    
    public static SensitivePropertyProviderFactory selectProviderFactory(String value) throws SensitivePropertyProtectionException {
        return selectProviderFactory(new PropertyMetadata().withPropertyValue(value));
    }
        

    public static SensitivePropertyProviderFactory selectProviderFactory(PropertyMetadata prop) throws SensitivePropertyProtectionException {
        if (AWSKMSSensitivePropertyProviderFactory.accepts(prop)) {
            logger.info("Selected AWS KMS sensitive property provider factory.");
            return new AWSKMSSensitivePropertyProviderFactory(prop);
        }

        if (AESSensitivePropertyProviderFactory.accepts(prop)) {
            logger.info("Selected AES sensitive property provider factory.");            
            return new AESSensitivePropertyProviderFactory(prop);
        }
        
        throw new SensitivePropertyProtectionException("Unable to select SensitivePropertyProviderFactory.");
    }
}
