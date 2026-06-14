/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.FederatedTokenDO;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotSame;

/**
 * Unit tests for {@link AuthorizationGrantCacheEntry}.
 */
public class AuthorizationGrantCacheEntryTest {

    @Mock
    private AuthenticatedUser mockAuthenticatedUser;
    @Mock
    private RequestObject mockRequestObject;
    @Mock
    private AccessTokenExtendedAttributes mockAccessTokenExtendedAttributes;
    @Mock
    private FederatedTokenDO mockFederatedTokenDO;

    @BeforeMethod
    public void setUp() {

        initMocks(this);
    }

    /**
     * Verifies that the copy constructor copies every declared field.
     *
     * If this test fails with "has the same value as an empty entry", a new field was added to
     * AuthorizationGrantCacheEntry but not set in buildFullyPopulatedEntry() — add it there.
     *
     * If this test fails with "was not copied by the copy constructor", the field exists in
     * buildFullyPopulatedEntry() but was not added to the copy constructor — add it there too.
     */
    @Test
    public void testCopyConstructorCopiesAllFields() throws IllegalAccessException {

        AuthorizationGrantCacheEntry empty = new AuthorizationGrantCacheEntry();
        AuthorizationGrantCacheEntry original = buildFullyPopulatedEntry();
        AuthorizationGrantCacheEntry copy = new AuthorizationGrantCacheEntry(original);

        Field amrListField = null;

        for (Field field : AuthorizationGrantCacheEntry.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())) {
                continue;
            }
            field.setAccessible(true);

            if ("amrList".equals(field.getName())) {
                amrListField = field;
            }

            assertNotEquals(field.get(original), field.get(empty),
                    "Field '" + field.getName() + "' has the same value as an empty entry. " +
                    "Set it to a non-default value in buildFullyPopulatedEntry().");

            assertEquals(field.get(copy), field.get(original),
                    "Field '" + field.getName() + "' was not copied by the copy constructor.");
        }

        // Verify userAttributes is a defensive copy — not the same map reference.
        assertNotSame(copy.getUserAttributes(), original.getUserAttributes());
        assertEquals(copy.getUserAttributes(), original.getUserAttributes());

        // Verify userAttributesList is a defensive copy — not the same array reference.
        assertNotSame(copy.getUserAttributesList(), original.getUserAttributesList());
        assertEquals(copy.getUserAttributesList(), original.getUserAttributesList());

        // Verify amrList is a defensive copy — not the same list reference.
        assertNotSame(amrListField.get(copy), amrListField.get(original));
        assertEquals(copy.getAmrList(), original.getAmrList());

        // Verify acrValue is a defensive copy — not the same set reference.
        assertNotSame(copy.getAcrValue(), original.getAcrValue());
        assertEquals(copy.getAcrValue(), original.getAcrValue());
    }

    private AuthorizationGrantCacheEntry buildFullyPopulatedEntry() {

        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry();

        ClaimMapping claimMapping = ClaimMapping.build("http://wso2.org/claims/username",
                "http://wso2.org/claims/username", null, false);
        Map<ClaimMapping, String> userAttributes = new HashMap<>(
                Collections.singletonMap(claimMapping, "john"));
        Map<ClaimMapping, String> mappedRemoteClaims = new HashMap<>(
                Collections.singletonMap(claimMapping, "john-remote"));

        LinkedHashSet<String> acrValues = new LinkedHashSet<>();
        acrValues.add("urn:mace:incommon:iap:silver");

        entry.setCodeId("code-id");
        entry.setAuthorizationCode("auth-code");
        entry.setTokenId("token-id");
        entry.setUserAttributes(userAttributes);
        entry.setNonceValue("nonce-value");
        entry.setPkceCodeChallenge("pkce-challenge");
        entry.setPkceCodeChallengeMethod("S256");
        entry.setAcrValue(acrValues);
        entry.setSelectedAcrValue("urn:mace:incommon:iap:silver");
        entry.addAmr("pwd");
        entry.setEssentialClaims("{\"id_token\":{\"acr\":{\"essential\":true}}}");
        entry.setAuthTime(1000L);
        entry.setMaxAge(3600L);
        entry.setRequestObject(mockRequestObject);
        entry.setHasNonOIDCClaims(true);
        entry.setMappedRemoteClaims(mappedRemoteClaims);
        entry.setSubjectClaim("john@carbon.super");
        entry.setTokenBindingValue("token-binding-value");
        entry.setSessionContextIdentifier("session-ctx-id");
        entry.setOidcSessionId("oidc-session-id");
        entry.setRequestObjectFlow(true);
        entry.setAuthenticatedUser(mockAuthenticatedUser);
        entry.setAccessTokenExtensionDO(mockAccessTokenExtendedAttributes);
        entry.setApiBasedAuthRequest(true);
        entry.setImpersonator("admin");
        entry.setFederatedTokens(Collections.singletonList(mockFederatedTokenDO));
        entry.setAudiences(Collections.singletonList("audience1"));
        entry.setCustomClaims(new HashMap<>(Collections.singletonMap("claim-key", "claim-value")));
        entry.setPreIssueAccessTokenActionsExecuted(true);
        entry.setUserAttributesList(new String[]{"username", "email"});

        return entry;
    }
}
