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
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.context.PropertyContext;
import org.apache.nifi.controller.ControllerService;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import java.util.Collection;


/**
 * This defines the interface for the PGP key material service.
 *
 */
public interface PGPKeyMaterialService extends ControllerService {
    PGPPublicKey getPublicKey(PropertyContext context);
    PGPPrivateKey getPrivateKey(PropertyContext context);
    char[] getPBEPassPhrase(PropertyContext context);

    PGPPublicKey getPublicKey();
    PGPPrivateKey getPrivateKey();
    char[] getPBEPassPhrase();

    Collection<ValidationResult> validateForEncrypt(PropertyContext context);
    Collection<ValidationResult> validateForDecrypt(PropertyContext context);
    Collection<ValidationResult> validateForSign(PropertyContext context);
    Collection<ValidationResult> validateForVerify(PropertyContext context);
}
