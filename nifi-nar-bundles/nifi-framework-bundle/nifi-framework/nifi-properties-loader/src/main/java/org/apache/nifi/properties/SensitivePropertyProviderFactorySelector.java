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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.apache.nifi.properties.sensitive.SensitivePropertyProtectionException;
import org.apache.nifi.properties.sensitive.SensitivePropertyProvider;
import org.apache.nifi.properties.sensitive.SensitivePropertyProviderFactory;
import org.apache.nifi.properties.sensitive.aes.AESSensitivePropertyProviderFactory;
import org.apache.nifi.properties.sensitive.aws.kms.AWSKMSSensitivePropertyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class SensitivePropertyProviderFactorySelector {
    private static final Logger logger = LoggerFactory.getLogger(SensitivePropertyProviderFactorySelector.class);
    
    public static SensitivePropertyProviderFactory selectProviderFactory(PropertyMetadata prop) throws SensitivePropertyProtectionException {
        logger.error("FAIL: " + prop.getPropertyValue());
        return new AESSensitivePropertyProviderFactory(prop.getPropertyValue());
    }
}

// SensitiveProviderFactorySelector
    //        AWS(AWSKMSSensitivePropertyProvider.class),
    //        AES(AESSensitivePropertyProvider.class);
    
    // same logic w/o reflection, use map;
    // update .getProvider() to .getProvider(String any) -> aes = key, aws = key id
    // send metadata to ctor


        // for (ProviderType providerType : ProviderType.values()) {
        //     Class <?> type = providerType.getType();
        //     try {
        //         if ((boolean) type.getMethod("canHandleScheme", String.class).invoke(null, selector)) {
        //             Constructor <?> ctor = type.getConstructor(String.class);
        //             return (SensitivePropertyProvider) ctor.newInstance(selector);
        //         }
        //     } catch (final NoSuchMethodException exc) {
        //         logger.error("Exception selecting provider: " + exc);
        //     } catch (final IllegalAccessException | InstantiationException | InvocationTargetException exc) {
        //         logger.error("Exception creating provider: " + exc);                
        //     }
        // }
        // throw new SensitivePropertyProtectionException("Could not create any provider");
