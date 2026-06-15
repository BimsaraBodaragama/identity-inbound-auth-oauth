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
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.optimizer.SessionDataOptimizationV2Exception;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizerUtil;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.cache.AuthorizationGrantDataOptimizer.AUTHORIZATION_GRANT_OPTIMIZATION_ENABLED;
import static org.wso2.carbon.identity.oauth.cache.AuthorizationGrantDataOptimizer.LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED;

/**
 * Unit tests for {@link AuthorizationGrantDataOptimizer}.
 */
public class AuthorizationGrantDataOptimizerTest {

    private static final String TEST_KEY = "test-auth-grant-key";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String LOCAL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String OIDC_CLAIM_URI = "http://wso2.org/oidc/claim/email";
    private static final String RUNTIME_CLAIM_URI = "http://wso2.org/claims/runtime";
    private static final String CLAIM_VALUE = "test@example.com";
    private static final String RUNTIME_CLAIM_VALUE = "runtimeValue";

    private AuthorizationGrantDataOptimizer optimizer;

    @Mock
    private AuthenticatedUser mockAuthenticatedUser;

    @Mock
    private ClaimMetadataHandler mockClaimMetadataHandler;

    private AutoCloseable mocks;

    @BeforeMethod
    public void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        optimizer = new AuthorizationGrantDataOptimizer();
    }

    @AfterMethod
    public void tearDown() throws Exception {
        mocks.close();
    }

    // ===== getCacheName =====

    @Test
    public void testGetCacheName() {
        assertEquals(optimizer.getCacheName(), "AuthorizationGrantCache");
    }

    // ===== isOptimizationEnabled =====

    @Test
    public void testIsOptimizationEnabled_WhenEnabled() {
        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    AUTHORIZATION_GRANT_OPTIMIZATION_ENABLED)).thenReturn(true);
            assertTrue(optimizer.isOptimizationEnabled());
        }
    }

    @Test
    public void testIsOptimizationEnabled_WhenDisabled() {
        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    AUTHORIZATION_GRANT_OPTIMIZATION_ENABLED)).thenReturn(false);
            assertFalse(optimizer.isOptimizationEnabled());
        }
    }

    // ===== optimizeSessionData =====

    @Test
    public void testOptimize_WhenLocalAttrOptimizationDisabled()
            throws SessionDataOptimizationV2Exception {

        Map<ClaimMapping, String> userAttributes = buildUserAttributes(false);
        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(false);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.optimize(TEST_KEY, entry);

            assertNull(result.getUserAttributesList(),
                    "userAttributesList should not be set when local attr optimization is disabled");
            assertEquals(result.getUserAttributes().size(), userAttributes.size());
            mockedUtil.verify(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()), never());
            mockedUtil.verify(() -> SessionDataOptimizerUtil.filterRuntimeClaims(any()), never());
        }
    }

    @Test
    public void testOptimize_WhenNoAuthenticatedUser() throws SessionDataOptimizationV2Exception {
        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry(buildUserAttributes(false));
        // No authenticated user set on entry

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.optimize(TEST_KEY, entry);

            assertNull(result.getUserAttributesList(),
                    "userAttributesList should not be set when authenticated user is null");
            mockedUtil.verify(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()), never());
        }
    }

    @Test
    public void testOptimize_WhenFederatedUser() throws SessionDataOptimizationV2Exception {
        Map<ClaimMapping, String> userAttributes = buildUserAttributes(false);
        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(true);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.optimize(TEST_KEY, entry);

            assertNull(result.getUserAttributesList(),
                    "userAttributesList should not be set for federated users");
            mockedUtil.verify(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()), never());
        }
    }

    @Test
    public void testOptimize_WhenLocalUserWithAttributes() throws SessionDataOptimizationV2Exception {
        // One normal claim + one runtime claim
        Map<ClaimMapping, String> userAttributes = buildUserAttributes(true);
        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        String[] expectedClaimURIs = {LOCAL_CLAIM_URI, RUNTIME_CLAIM_URI};
        ClaimMapping runtimeMapping = ClaimMapping.build(RUNTIME_CLAIM_URI, RUNTIME_CLAIM_URI, null, false);
        runtimeMapping.setIsRuntimeValue(true);
        Map<ClaimMapping, String> filteredAttributes = new HashMap<>();
        filteredAttributes.put(runtimeMapping, RUNTIME_CLAIM_VALUE);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()))
                    .thenReturn(expectedClaimURIs);
            mockedUtil.when(() -> SessionDataOptimizerUtil.filterRuntimeClaims(any()))
                    .thenReturn(filteredAttributes);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.optimize(TEST_KEY, entry);

            assertNotNull(result.getUserAttributesList());
            assertEquals(result.getUserAttributesList(), expectedClaimURIs);
            assertEquals(result.getUserAttributes(), filteredAttributes,
                    "userAttributes should contain only runtime claims after filtering");
        }
    }

    @Test
    public void testOptimize_WhenLocalUserWithEmptyAttributes() throws SessionDataOptimizationV2Exception {
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()))
                    .thenReturn(new String[0]);
            mockedUtil.when(() -> SessionDataOptimizerUtil.filterRuntimeClaims(any()))
                    .thenReturn(new HashMap<>());

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.optimize(TEST_KEY, entry);

            assertNotNull(result.getUserAttributesList());
            assertEquals(result.getUserAttributesList().length, 0);
            assertTrue(result.getUserAttributes().isEmpty());
        }
    }

    @Test
    public void testOptimize_DoesNotModifyOriginalEntry() throws SessionDataOptimizationV2Exception {
        Map<ClaimMapping, String> userAttributes = buildUserAttributes(false);
        AuthorizationGrantCacheEntry originalEntry = buildEntry(userAttributes, mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()))
                    .thenReturn(new String[]{LOCAL_CLAIM_URI});
            mockedUtil.when(() -> SessionDataOptimizerUtil.filterRuntimeClaims(any()))
                    .thenReturn(new HashMap<>());

            optimizer.optimize(TEST_KEY, originalEntry);

            // The optimizer creates a copy; the original entry must not be mutated
            assertNull(originalEntry.getUserAttributesList(),
                    "Original entry userAttributesList must not be modified by the optimizer");
            assertEquals(originalEntry.getUserAttributes().size(), userAttributes.size(),
                    "Original entry userAttributes must not be modified by the optimizer");
        }
    }

    // ===== loadSessionData =====

    @Test
    public void testLoad_WhenLocalAttrOptimizationDisabled() throws SessionDataOptimizationV2Exception {
        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry();
        entry.setUserAttributes(buildUserAttributes(false));
        entry.setUserAttributesList(new String[]{LOCAL_CLAIM_URI});

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(false);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNotNull(result.getUserAttributesList(),
                    "userAttributesList should remain unchanged when optimization is disabled");
            mockedUtil.verify(
                    () -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(any(), any()), never());
        }
    }

    @Test
    public void testLoad_WhenUserAttributesListIsNull() throws SessionDataOptimizationV2Exception {
        AuthorizationGrantCacheEntry entry = buildEntry(buildUserAttributes(false), mockAuthenticatedUser);
        // userAttributesList is null by default — indicates entry was not optimized

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList());
            mockedUtil.verify(
                    () -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(any(), any()), never());
        }
    }

    @Test
    public void testLoad_WhenNoAuthenticatedUser() throws SessionDataOptimizationV2Exception {
        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry();
        entry.setUserAttributes(buildUserAttributes(false));
        entry.setUserAttributesList(new String[]{LOCAL_CLAIM_URI});
        // No authenticated user

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNotNull(result.getUserAttributesList(),
                    "userAttributesList should remain set when authenticated user is absent");
            mockedUtil.verify(
                    () -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(any(), any()), never());
        }
    }

    @Test
    public void testLoad_WhenFederatedUser() throws SessionDataOptimizationV2Exception {
        Map<ClaimMapping, String> userAttributes = buildUserAttributes(false);
        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{LOCAL_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(true);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNotNull(result.getUserAttributesList(),
                    "userAttributesList should remain set for federated users");
            mockedUtil.verify(
                    () -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(any(), any()), never());
        }
    }

    @Test
    public void testLoad_WhenEmptyUserAttributesList() throws SessionDataOptimizationV2Exception {
        // userAttributesList is empty: all non-runtime claims were removed but none need to be re-fetched
        Map<ClaimMapping, String> userAttributes = buildUserAttributes(false);
        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        entry.setUserAttributesList(new String[0]);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        ClaimMapping rebuiltMapping = ClaimMapping.build(LOCAL_CLAIM_URI, LOCAL_CLAIM_URI, null, false);
        Map<ClaimMapping, String> rebuiltAttributes = new HashMap<>();
        rebuiltAttributes.put(rebuiltMapping, CLAIM_VALUE);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedFwUtil.when(() -> FrameworkUtils.buildClaimMappings(any(Map.class)))
                    .thenReturn(rebuiltAttributes);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList(),
                    "userAttributesList should be null after a successful reset");
            assertEquals(result.getUserAttributes(), rebuiltAttributes);
            mockedUtil.verify(() -> SessionDataOptimizerUtil.getUserClaimValues(any(), any()), never());
        }
    }

    @Test
    public void testLoad_WhenAllClaimsAlreadyPresent() throws SessionDataOptimizationV2Exception {
        // userAttributesList names a claim that is already present in userAttributes —
        // no OIDC lookup or user store call should be made
        ClaimMapping existingMapping = ClaimMapping.build(LOCAL_CLAIM_URI, LOCAL_CLAIM_URI, null, false);
        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        userAttributes.put(existingMapping, CLAIM_VALUE);

        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{LOCAL_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        ClaimMapping rebuiltMapping = ClaimMapping.build(LOCAL_CLAIM_URI, LOCAL_CLAIM_URI, null, false);
        Map<ClaimMapping, String> rebuiltAttributes = new HashMap<>();
        rebuiltAttributes.put(rebuiltMapping, CLAIM_VALUE);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedFwUtil.when(() -> FrameworkUtils.buildClaimMappings(any(Map.class)))
                    .thenReturn(rebuiltAttributes);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList());
            // No OIDC dialect lookup needed when all claims are already present
            mockedClaimMetadata.verify(ClaimMetadataHandler::getInstance, never());
        }
    }

    @Test
    public void testLoad_WhenClaimMetadataExceptionOccurs() throws Exception {
        // OIDC claim present in userAttributesList but absent from userAttributes;
        // ClaimMetadataHandler throws — the optimizer must fall back gracefully
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedClaimMetadata.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
            when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                    anyString(), anySet(), anyString(), anyBoolean()))
                    .thenThrow(new ClaimMetadataException("Simulated metadata error"));
            mockedFwUtil.when(() -> FrameworkUtils.buildClaimMappings(any(Map.class)))
                    .thenReturn(new HashMap<>());

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList(),
                    "userAttributesList should be cleared even when ClaimMetadataException occurs");
            mockedUtil.verify(() -> SessionDataOptimizerUtil.getUserClaimValues(any(), any()), never());
        }
    }

    @Test
    public void testLoad_WhenOIDCMappingIsEmpty() throws Exception {
        // OIDC claim present in userAttributesList but ClaimMetadataHandler returns an empty mapping
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedClaimMetadata.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
            when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                    anyString(), anySet(), anyString(), anyBoolean()))
                    .thenReturn(Collections.emptyMap());
            mockedFwUtil.when(() -> FrameworkUtils.buildClaimMappings(any(Map.class)))
                    .thenReturn(new HashMap<>());

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList());
            mockedUtil.verify(() -> SessionDataOptimizerUtil.getUserClaimValues(any(), any()), never());
        }
    }

    @Test
    public void testLoad_WhenClaimsResolvedFromUserStore() throws Exception {
        // Missing OIDC claim is resolved through ClaimMetadataHandler and then fetched from the user store
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(OIDC_CLAIM_URI, LOCAL_CLAIM_URI);

        Map<String, String> userStoreClaimValues = new HashMap<>();
        userStoreClaimValues.put(LOCAL_CLAIM_URI, CLAIM_VALUE);

        ClaimMapping resolvedMapping = ClaimMapping.build(OIDC_CLAIM_URI, OIDC_CLAIM_URI, null, false);
        Map<ClaimMapping, String> rebuiltAttributes = new HashMap<>();
        rebuiltAttributes.put(resolvedMapping, CLAIM_VALUE);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedUtil.when(() -> SessionDataOptimizerUtil.getUserClaimValues(
                    any(AuthenticatedUser.class), any(String[].class)))
                    .thenReturn(userStoreClaimValues);
            mockedClaimMetadata.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
            when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                    anyString(), anySet(), anyString(), anyBoolean()))
                    .thenReturn(oidcToCarbonMapping);
            mockedFwUtil.when(() -> FrameworkUtils.buildClaimMappings(any(Map.class)))
                    .thenReturn(rebuiltAttributes);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList());
            assertEquals(result.getUserAttributes(), rebuiltAttributes);
            mockedUtil.verify(() -> SessionDataOptimizerUtil.getUserClaimValues(
                    eq(mockAuthenticatedUser), any(String[].class)));
        }
    }

    @Test
    public void testLoad_WhenSomeClaimsHaveNoLocalMapping() throws Exception {
        // OIDC claim is in claimsToResolveSet but its mapped local claim URI is blank — it must be silently skipped
        String unmappedOidcClaimUri = "http://wso2.org/oidc/claim/unmapped";
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{unmappedOidcClaimUri});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(unmappedOidcClaimUri, ""); // blank local URI — no mapping

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedUtil.when(() -> SessionDataOptimizerUtil.getUserClaimValues(
                    any(AuthenticatedUser.class), any(String[].class)))
                    .thenReturn(new HashMap<>());
            mockedClaimMetadata.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
            when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                    anyString(), anySet(), anyString(), anyBoolean()))
                    .thenReturn(oidcToCarbonMapping);
            mockedFwUtil.when(() -> FrameworkUtils.buildClaimMappings(any(Map.class)))
                    .thenReturn(new HashMap<>());

            // Must complete without exception; the unmapped claim is just skipped
            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList());
        }
    }

    @Test
    public void testLoad_RuntimeClaimsRestoredCorrectly() throws SessionDataOptimizationV2Exception {
        // A runtime claim surviving in userAttributes must have isRuntimeValue re-applied after
        // concludeLocalAttributeOptimizationReset rebuilds the claim mappings via buildClaimMappings
        ClaimMapping runtimeMapping = ClaimMapping.build(RUNTIME_CLAIM_URI, RUNTIME_CLAIM_URI, null, false);
        runtimeMapping.setIsRuntimeValue(true);
        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        userAttributes.put(runtimeMapping, RUNTIME_CLAIM_VALUE);

        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        entry.setUserAttributesList(new String[0]); // empty: no claims to re-fetch
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        // buildClaimMappings returns a fresh mapping without isRuntimeValue set (simulates what the real method does)
        ClaimMapping freshRuntimeMapping = ClaimMapping.build(RUNTIME_CLAIM_URI, RUNTIME_CLAIM_URI, null, false);
        Map<ClaimMapping, String> rebuiltAttributes = new HashMap<>();
        rebuiltAttributes.put(freshRuntimeMapping, RUNTIME_CLAIM_VALUE);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedFwUtil.when(() -> FrameworkUtils.buildClaimMappings(any(Map.class)))
                    .thenReturn(rebuiltAttributes);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList());
            result.getUserAttributes().forEach((claimMapping, value) -> {
                if (RUNTIME_CLAIM_URI.equals(claimMapping.getLocalClaim().getClaimUri())) {
                    assertTrue(claimMapping.isRuntimeValue(),
                            "Runtime claim should have isRuntimeValue restored to true after reset");
                }
            });
        }
    }

    // ===== Helpers =====

    private Map<ClaimMapping, String> buildUserAttributes(boolean includeRuntimeClaim) {
        Map<ClaimMapping, String> attributes = new HashMap<>();
        ClaimMapping normalMapping = ClaimMapping.build(LOCAL_CLAIM_URI, LOCAL_CLAIM_URI, null, false);
        attributes.put(normalMapping, CLAIM_VALUE);
        if (includeRuntimeClaim) {
            ClaimMapping runtimeMapping = ClaimMapping.build(RUNTIME_CLAIM_URI, RUNTIME_CLAIM_URI, null, false);
            runtimeMapping.setIsRuntimeValue(true);
            attributes.put(runtimeMapping, RUNTIME_CLAIM_VALUE);
        }
        return attributes;
    }

    private AuthorizationGrantCacheEntry buildEntry(Map<ClaimMapping, String> userAttributes,
                                                    AuthenticatedUser authenticatedUser) {
        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry(userAttributes);
        if (authenticatedUser != null) {
            entry.setAuthenticatedUser(authenticatedUser);
        }
        return entry;
    }
}
