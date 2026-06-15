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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.optimizer.SessionDataOptimizationV2Exception;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizer;
import org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizerUtil;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class optimizes the Authorization grant data before storing it in the database and loads it back
 * to the original form when retrieving from the database.
 */
public class AuthorizationGrantDataOptimizer implements SessionDataOptimizer {

    public static final String AUTHORIZATION_GRANT_OPTIMIZATION_ENABLED
            = "SessionDataOptimizationV2.AuthorizationGrant.Enable";
    public static final String LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED
            = "SessionDataOptimizationV2.AuthorizationGrant.OptimizeLocalUserAttributes";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    private static final Log LOG = LogFactory.getLog(AuthorizationGrantDataOptimizer.class);

    @Override
    public String getCacheName() {

        return "AuthorizationGrantCache";
    }

    @Override
    public boolean isOptimizationEnabled() {

        return SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                AUTHORIZATION_GRANT_OPTIMIZATION_ENABLED);
    }

    @Override
    public Object optimize(String key, Object entry) throws SessionDataOptimizationV2Exception {

        AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                new AuthorizationGrantCacheEntry((AuthorizationGrantCacheEntry) entry);

        if (!isLocalUserAttributeOptimizationEnabled()) {
            return authorizationGrantCacheEntry;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Local user attribute optimization is enabled. Optimizing local user attributes in " +
                    "AuthorizationGrantCacheEntry with key: " + key);
        }
        optimizeLocalUserAttributes(authorizationGrantCacheEntry, key);
        return authorizationGrantCacheEntry;
    }

    @Override
    public Object load(String key, Object entry) throws SessionDataOptimizationV2Exception {

        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = (AuthorizationGrantCacheEntry) entry;
        rebuildLocalUserAttributes(authorizationGrantCacheEntry, key);
        return authorizationGrantCacheEntry;
    }

    private void optimizeLocalUserAttributes(AuthorizationGrantCacheEntry entry, String keyId) {

        if (entry.getAuthenticatedUser() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No authenticated user found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Skipping optimization of local user attributes.");
            }
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authenticated user found in AuthorizationGrantCacheEntry with key: " + keyId +
                    ". Proceeding with optimization of local user attributes.");
        }

        AuthenticatedUser authenticatedUser = entry.getAuthenticatedUser();
        if (authenticatedUser.isFederatedUser()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Federated user found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Skipping optimization of local user attributes.");
            }
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Optimizing local user attributes in AuthorizationGrantCacheEntry with key: " + keyId);
        }

        if (MapUtils.isEmpty(entry.getUserAttributes())) {
            if  (LOG.isDebugEnabled()) {
                LOG.debug("No user attributes found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Skipping optimization of local user attributes.");
            }
            return;
        }

        String[] claimURIList = SessionDataOptimizerUtil.getUserClaimURIsArray(entry.getUserAttributes());
        entry.setUserAttributesList(claimURIList);

        entry.setUserAttributes(SessionDataOptimizerUtil.filterRuntimeClaims(entry.getUserAttributes()));

        if  (LOG.isDebugEnabled()) {
            LOG.debug("Optimized local user attributes for authorization grant cache entry with key: " + keyId);
        }
    }

    private void rebuildLocalUserAttributes(AuthorizationGrantCacheEntry entry, String keyId)
            throws SessionDataOptimizationV2Exception {

        if (entry.getUserAttributesList() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No user attributes list found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Skipping restoration of local user attributes.");
            }
            return;
        }

        AuthenticatedUser authenticatedUser = entry.getAuthenticatedUser();
        if (authenticatedUser == null) {
            throw new SessionDataOptimizationV2Exception(
                    "No authenticated user found in AuthorizationGrantCacheEntry even though optimization metadata " +
                            "exists for authorization grant cache entry with key: " + keyId);
        }
        if (authenticatedUser.isFederatedUser()) {
            throw new SessionDataOptimizationV2Exception(
                    "Authenticated user is a federated user even though local user attribute optimization was " +
                            "applied for authorization grant cache entry with key: " + keyId);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Restoring user attributes in AuthorizationGrantCacheEntry with key: " + keyId);
        }

        Map<String, String> userAttributesMap = new HashMap<>();
        Set<String> runtimeClaimURIs = new HashSet<>();
        entry.getUserAttributes().forEach(((claimMapping, value) -> {
            userAttributesMap.put(claimMapping.getLocalClaim().getClaimUri(), value);
            if (claimMapping.isRuntimeValue()) {
                runtimeClaimURIs.add(claimMapping.getLocalClaim().getClaimUri());
            }
        }));
        SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims(authenticatedUser, userAttributesMap);

        String[] claimsToResolve = entry.getUserAttributesList();
        if (claimsToResolve.length == 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No user attributes to restore for authorization grant cache entry with key: " + keyId);
            }
            setUserAttributesToAuthorizationGrantCacheEntry(entry, userAttributesMap, runtimeClaimURIs);
            return;
        }

        Set<String> claimsToResolveSet = new HashSet<>(Arrays.asList(claimsToResolve));
        claimsToResolveSet.removeIf(userAttributesMap::containsKey);

        if (claimsToResolveSet.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("All user attributes to restore for authorization grant cache entry with key: "
                        + keyId + " are already present in the user attributes map. No need to retrieve " +
                        "from user store.");
            }
            setUserAttributesToAuthorizationGrantCacheEntry(entry, userAttributesMap, runtimeClaimURIs);
            return;
        }

        Map<String, String> oidcToCarbonClaimMapping;
        try {
            oidcToCarbonClaimMapping = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, claimsToResolveSet,
                            authenticatedUser.getTenantDomain(), false);
        } catch (ClaimMetadataException e) {
            throw new SessionDataOptimizationV2Exception(
                    "Error while retrieving claim mappings from claim metadata for dialect: " +
                            OIDC_DIALECT + " in the authorization grant cache entry with key: " + keyId, e);
        }

        if (oidcToCarbonClaimMapping.isEmpty()) {
            throw new SessionDataOptimizationV2Exception(
                    "No OIDC dialect claim mappings found even though claims remain to be rebuilt " +
                            "for authorization grant cache entry with key: " + keyId);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Continue rebuilding local user attributes from the user store for authorization grant " +
                    "cache entry with key: " + keyId);
        }

        Map<String, String> userClaimsFromUserStore = SessionDataOptimizerUtil.getUserClaimValues(
                authenticatedUser, oidcToCarbonClaimMapping.values().toArray(new String[0]));

        if (MapUtils.isEmpty(userClaimsFromUserStore)) {
            throw new SessionDataOptimizationV2Exception(
                    "No user claims retrieved from the user store even after claims remaining to be rebuilt " +
                            "from the user store for authorization grant cache entry with key: " + keyId);
        }

        Set<String> resolvedClaims = new HashSet<>();
        for (String claimUri : claimsToResolveSet) {
            String localDialectClaimUri = oidcToCarbonClaimMapping.get(claimUri);
            if (StringUtils.isEmpty(localDialectClaimUri)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No local claim mapping found for claim URI: " + claimUri + ". Skipping this claim.");
                }
                continue;
            }
            String claimValue = userClaimsFromUserStore.get(localDialectClaimUri);
            if  (StringUtils.isNotEmpty(claimValue)) {
                resolvedClaims.add(claimUri);
                userAttributesMap.put(claimUri, claimValue);
            }
        }
        claimsToResolveSet.removeAll(resolvedClaims);

        if (!claimsToResolveSet.isEmpty()) {
            throw new SessionDataOptimizationV2Exception(
                    "Error while rebuilding local user attributes from the user store. Unable to retrieve values for " +
                            "claim URIs: " + claimsToResolveSet + " for authorization grant cache entry with key: " +
                            keyId);
        }

        if  (LOG.isDebugEnabled()) {
            LOG.debug("Completed retrieving local user attributes from the user store. Concluding the rebuilding " +
                    "of local user attributes for authorization grant cache entry with key: " + keyId);
        }

        setUserAttributesToAuthorizationGrantCacheEntry(entry, userAttributesMap, runtimeClaimURIs);

        if  (LOG.isDebugEnabled()) {
            LOG.debug("Restored local user attributes for authorization grant cache entry with key: " + keyId);
        }
    }

    private void setUserAttributesToAuthorizationGrantCacheEntry(AuthorizationGrantCacheEntry entry,
                                                                 Map<String, String> userAttributesMap,
                                                                 Set<String> runtimeClaimURIs) {

        Map<ClaimMapping, String> finalClaimMappings = FrameworkUtils.buildClaimMappings(userAttributesMap);
        finalClaimMappings.forEach((claimMapping, value) -> {
            if (runtimeClaimURIs.contains(claimMapping.getLocalClaim().getClaimUri())) {
                claimMapping.setRuntimeValue(true);
            }
        });
        entry.setUserAttributes(finalClaimMappings);
        entry.setUserAttributesList(null);
    }

    private boolean isLocalUserAttributeOptimizationEnabled() {

        return SessionDataOptimizerUtil.isSessionDataOptimizationV2ConfigEnabled(
                LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED);
    }
}
