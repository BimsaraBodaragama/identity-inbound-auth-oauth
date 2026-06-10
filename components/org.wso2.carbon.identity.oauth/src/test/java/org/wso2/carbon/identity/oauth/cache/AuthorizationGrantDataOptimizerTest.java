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
    private static final String LOCAL_CLAIM_URI_2 = "http://wso2.org/claims/givenname";
    private static final String OIDC_CLAIM_URI = "http://wso2.org/oidc/claim/email";
    private static final String OIDC_CLAIM_URI_2 = "http://wso2.org/oidc/claim/given_name";
    private static final String RUNTIME_CLAIM_URI = "http://wso2.org/claims/runtime";
    private static final String CLAIM_VALUE = "test@example.com";
    private static final String CLAIM_VALUE_2 = "John";
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
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    AUTHORIZATION_GRANT_OPTIMIZATION_ENABLED)).thenReturn(true);
            assertTrue(optimizer.isOptimizationEnabled());
        }
    }

    @Test
    public void testIsOptimizationEnabled_WhenDisabled() {
        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
        // Empty userAttributes — optimization is skipped entirely
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.optimize(TEST_KEY, entry);

            assertNull(result.getUserAttributesList(),
                    "userAttributesList should not be set when userAttributes is empty");
            assertTrue(result.getUserAttributes().isEmpty());
            mockedUtil.verify(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()), never());
            mockedUtil.verify(() -> SessionDataOptimizerUtil.filterRuntimeClaims(any()), never());
        }
    }

    @Test
    public void testOptimize_DoesNotModifyOriginalEntry() throws SessionDataOptimizationV2Exception {
        Map<ClaimMapping, String> userAttributes = buildUserAttributes(false);
        AuthorizationGrantCacheEntry originalEntry = buildEntry(userAttributes, mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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

    @Test
    public void testOptimize_WhenAllClaimsAreRuntimeClaims() throws SessionDataOptimizationV2Exception {
        // All user attributes are runtime claims — getUserClaimURIsArray returns [] (nothing to re-fetch),
        // filterRuntimeClaims keeps them all. userAttributesList should be set to an empty array.
        ClaimMapping runtimeMapping = ClaimMapping.build(RUNTIME_CLAIM_URI, RUNTIME_CLAIM_URI, null, false);
        runtimeMapping.setIsRuntimeValue(true);
        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        userAttributes.put(runtimeMapping, RUNTIME_CLAIM_VALUE);

        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        Map<ClaimMapping, String> filteredAttributes = new HashMap<>(userAttributes);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()))
                    .thenReturn(new String[0]);
            mockedUtil.when(() -> SessionDataOptimizerUtil.filterRuntimeClaims(any()))
                    .thenReturn(filteredAttributes);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.optimize(TEST_KEY, entry);

            assertNotNull(result.getUserAttributesList(),
                    "userAttributesList should be set (empty array) to signal optimization ran");
            assertEquals(result.getUserAttributesList().length, 0,
                    "userAttributesList should be empty when all claims are runtime");
            assertEquals(result.getUserAttributes(), filteredAttributes,
                    "All runtime claims should remain in userAttributes");
        }
    }

    @Test
    public void testOptimize_WhenLocalUserWithOnlyNonRuntimeClaims() throws SessionDataOptimizationV2Exception {
        // Only non-runtime claims — filterRuntimeClaims strips them all, leaving an empty userAttributes.
        // userAttributesList should hold all the claim URIs for later re-fetch.
        Map<ClaimMapping, String> userAttributes = buildUserAttributes(false);
        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);

        String[] expectedClaimURIs = {LOCAL_CLAIM_URI};

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.getUserClaimURIsArray(any()))
                    .thenReturn(expectedClaimURIs);
            mockedUtil.when(() -> SessionDataOptimizerUtil.filterRuntimeClaims(any()))
                    .thenReturn(new HashMap<>());

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.optimize(TEST_KEY, entry);

            assertNotNull(result.getUserAttributesList());
            assertEquals(result.getUserAttributesList(), expectedClaimURIs,
                    "All non-runtime claim URIs should be stored for re-fetch");
            assertTrue(result.getUserAttributes().isEmpty(),
                    "userAttributes should be empty after all non-runtime claims are stripped");
        }
    }

    // ===== loadSessionData =====

    @Test
    public void testLoad_WhenLocalAttrOptimizationDisabled() throws SessionDataOptimizationV2Exception {
        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry();
        entry.setUserAttributes(buildUserAttributes(false));
        entry.setUserAttributesList(new String[]{LOCAL_CLAIM_URI});

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            AuthorizationGrantCacheEntry result =
                    (AuthorizationGrantCacheEntry) optimizer.load(TEST_KEY, entry);

            assertNull(result.getUserAttributesList());
            mockedUtil.verify(
                    () -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(any(), any()), never());
        }
    }

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenNoAuthenticatedUser() throws SessionDataOptimizationV2Exception {
        // userAttributesList is set but there is no authenticated user — data integrity violation
        AuthorizationGrantCacheEntry entry = new AuthorizationGrantCacheEntry();
        entry.setUserAttributes(buildUserAttributes(false));
        entry.setUserAttributesList(new String[]{LOCAL_CLAIM_URI});

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            optimizer.load(TEST_KEY, entry);
        }
    }

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenFederatedUser() throws SessionDataOptimizationV2Exception {
        // userAttributesList is set but the user is federated — data integrity violation
        Map<ClaimMapping, String> userAttributes = buildUserAttributes(false);
        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{LOCAL_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(true);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class)) {
            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);

            optimizer.load(TEST_KEY, entry);
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

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenClaimMetadataExceptionOccurs() throws Exception {
        // OIDC claim present in userAttributesList but absent from userAttributes;
        // ClaimMetadataHandler throws — the optimizer must propagate as SessionDataOptimizationV2Exception
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedClaimMetadata.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
            when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                    anyString(), anySet(), anyString(), anyBoolean()))
                    .thenThrow(new ClaimMetadataException("Simulated metadata error"));

            optimizer.load(TEST_KEY, entry);
        }
    }

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenOIDCMappingIsEmpty() throws Exception {
        // OIDC claim present in userAttributesList but ClaimMetadataHandler returns an empty mapping —
        // the claims cannot be resolved so the optimizer must throw
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedClaimMetadata.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
            when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                    anyString(), anySet(), anyString(), anyBoolean()))
                    .thenReturn(Collections.emptyMap());

            optimizer.load(TEST_KEY, entry);
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

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
    public void testLoad_WhenMultipleClaimsAllResolvedFromUserStore() throws Exception {
        // Two OIDC claims, both resolved via ClaimMetadataHandler and the user store.
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI, OIDC_CLAIM_URI_2});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(OIDC_CLAIM_URI, LOCAL_CLAIM_URI);
        oidcToCarbonMapping.put(OIDC_CLAIM_URI_2, LOCAL_CLAIM_URI_2);

        Map<String, String> userStoreClaimValues = new HashMap<>();
        userStoreClaimValues.put(LOCAL_CLAIM_URI, CLAIM_VALUE);
        userStoreClaimValues.put(LOCAL_CLAIM_URI_2, CLAIM_VALUE_2);

        ClaimMapping resolvedMapping1 = ClaimMapping.build(OIDC_CLAIM_URI, OIDC_CLAIM_URI, null, false);
        ClaimMapping resolvedMapping2 = ClaimMapping.build(OIDC_CLAIM_URI_2, OIDC_CLAIM_URI_2, null, false);
        Map<ClaimMapping, String> rebuiltAttributes = new HashMap<>();
        rebuiltAttributes.put(resolvedMapping1, CLAIM_VALUE);
        rebuiltAttributes.put(resolvedMapping2, CLAIM_VALUE_2);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
            assertEquals(result.getUserAttributes().size(), 2,
                    "Both OIDC claims should be present in the rebuilt attributes");
        }
    }

    @Test
    public void testLoad_WhenRuntimeAndNonRuntimeClaimsRebuilt() throws Exception {
        // Entry has a surviving runtime claim in userAttributes (from optimize) AND an OIDC claim
        // to rebuild from the user store. After load, both should be present and the runtime
        // claim should have isRuntimeValue re-applied.
        ClaimMapping runtimeMapping = ClaimMapping.build(RUNTIME_CLAIM_URI, RUNTIME_CLAIM_URI, null, false);
        runtimeMapping.setIsRuntimeValue(true);
        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        userAttributes.put(runtimeMapping, RUNTIME_CLAIM_VALUE);

        AuthorizationGrantCacheEntry entry = buildEntry(userAttributes, mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(OIDC_CLAIM_URI, LOCAL_CLAIM_URI);

        Map<String, String> userStoreClaimValues = new HashMap<>();
        userStoreClaimValues.put(LOCAL_CLAIM_URI, CLAIM_VALUE);

        ClaimMapping freshRuntimeMapping = ClaimMapping.build(RUNTIME_CLAIM_URI, RUNTIME_CLAIM_URI, null, false);
        ClaimMapping rebuiltOidcMapping = ClaimMapping.build(OIDC_CLAIM_URI, OIDC_CLAIM_URI, null, false);
        Map<ClaimMapping, String> rebuiltAttributes = new HashMap<>();
        rebuiltAttributes.put(freshRuntimeMapping, RUNTIME_CLAIM_VALUE);
        rebuiltAttributes.put(rebuiltOidcMapping, CLAIM_VALUE);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<FrameworkUtils> mockedFwUtil = mockStatic(FrameworkUtils.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
            assertEquals(result.getUserAttributes().size(), 2,
                    "Both the runtime claim and the rebuilt OIDC claim should be present");
            result.getUserAttributes().forEach((claimMapping, value) -> {
                if (RUNTIME_CLAIM_URI.equals(claimMapping.getLocalClaim().getClaimUri())) {
                    assertTrue(claimMapping.isRuntimeValue(),
                            "Runtime claim should have isRuntimeValue restored after rebuild");
                }
            });
        }
    }

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenUserStoreReturnsEmptyForValidOIDCMapping() throws Exception {
        // Valid OIDC→local mapping returned by ClaimMetadataHandler, but the user store returns
        // no values for the resolved local claims — optimizer must throw
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(OIDC_CLAIM_URI, LOCAL_CLAIM_URI);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                    LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED)).thenReturn(true);
            mockedUtil.when(() -> SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(
                    any(AuthenticatedUser.class), any(Map.class))).then(inv -> null);
            mockedUtil.when(() -> SessionDataOptimizerUtil.getUserClaimValues(
                    any(AuthenticatedUser.class), any(String[].class)))
                    .thenReturn(Collections.emptyMap());
            mockedClaimMetadata.when(ClaimMetadataHandler::getInstance).thenReturn(mockClaimMetadataHandler);
            when(mockClaimMetadataHandler.getMappingsMapFromOtherDialectToCarbon(
                    anyString(), anySet(), anyString(), anyBoolean()))
                    .thenReturn(oidcToCarbonMapping);

            optimizer.load(TEST_KEY, entry);
        }
    }

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenUserStoreClaimValueIsAbsent() throws Exception {
        // User store returns a non-empty map but does not contain a value for the requested local
        // claim URI — the OIDC claim remains unresolved and the optimizer must throw
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(OIDC_CLAIM_URI, LOCAL_CLAIM_URI);

        // User store returns non-empty but for a completely different claim URI
        Map<String, String> userStoreClaimValues = new HashMap<>();
        userStoreClaimValues.put("http://wso2.org/claims/other", "someValue");

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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

            optimizer.load(TEST_KEY, entry);
        }
    }

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenMultipleClaimsPartiallyResolvedFromUserStore() throws Exception {
        // Two OIDC claims to resolve; user store returns a value for one but not the other —
        // the remaining unresolved claim causes a throw
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI, OIDC_CLAIM_URI_2});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(OIDC_CLAIM_URI, LOCAL_CLAIM_URI);
        oidcToCarbonMapping.put(OIDC_CLAIM_URI_2, LOCAL_CLAIM_URI_2);

        // Only the first claim is resolved from the user store
        Map<String, String> userStoreClaimValues = new HashMap<>();
        userStoreClaimValues.put(LOCAL_CLAIM_URI, CLAIM_VALUE);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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

            optimizer.load(TEST_KEY, entry);
        }
    }

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenBlankLocalMappingWithOtherClaimsResolving() throws Exception {
        // Two OIDC claims: one maps to a valid local URI (resolved from user store), the other
        // has a blank local URI (skipped in the resolution loop). The blank-mapped claim remains
        // unresolved after the loop completes, causing a throw.
        String unmappedOidcClaimUri = "http://wso2.org/oidc/claim/unmapped";
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{OIDC_CLAIM_URI, unmappedOidcClaimUri});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(OIDC_CLAIM_URI, LOCAL_CLAIM_URI);
        oidcToCarbonMapping.put(unmappedOidcClaimUri, ""); // blank — skipped in the loop

        // User store returns a non-empty result for the valid claim, so the empty-map guard passes
        Map<String, String> userStoreClaimValues = new HashMap<>();
        userStoreClaimValues.put(LOCAL_CLAIM_URI, CLAIM_VALUE);

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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

            optimizer.load(TEST_KEY, entry);
        }
    }

    @Test(expectedExceptions = SessionDataOptimizationV2Exception.class)
    public void testLoad_WhenSomeClaimsHaveNoLocalMapping() throws Exception {
        // OIDC claim has a blank local URI mapping and the user store returns no values —
        // the claim cannot be resolved so the optimizer must throw
        String unmappedOidcClaimUri = "http://wso2.org/oidc/claim/unmapped";
        AuthorizationGrantCacheEntry entry = buildEntry(new HashMap<>(), mockAuthenticatedUser);
        entry.setUserAttributesList(new String[]{unmappedOidcClaimUri});
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(mockAuthenticatedUser.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Map<String, String> oidcToCarbonMapping = new HashMap<>();
        oidcToCarbonMapping.put(unmappedOidcClaimUri, ""); // blank local URI — no mapping

        try (MockedStatic<SessionDataOptimizerUtil> mockedUtil = mockStatic(SessionDataOptimizerUtil.class);
             MockedStatic<ClaimMetadataHandler> mockedClaimMetadata = mockStatic(ClaimMetadataHandler.class)) {

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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

            optimizer.load(TEST_KEY, entry);
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

            mockedUtil.when(() -> SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
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
