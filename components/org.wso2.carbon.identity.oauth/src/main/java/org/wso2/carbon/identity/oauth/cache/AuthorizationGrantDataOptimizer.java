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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.optimizer.SessionDataOptimizationV2Exception;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.optimizer.AbstractSessionDataOptimizer;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataHandler;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizerUtil.addMultiAttributeSeparatorToUserClaims;
import static org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizerUtil.filterRuntimeClaims;
import static org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizerUtil.getSessionDataOptimizationV2ConfigValue;
import static org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizerUtil.getUserClaimURIsArray;
import static org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizerUtil.getUserClaimValues;
import static org.wso2.carbon.identity.application.authentication.framework.optimizer.SessionDataOptimizerUtil.logSessionDataIntoConsole;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.buildClaimMappings;

/**
 * This class optimizes the Authorization grant data before storing it in the database and loads it back
 * to the original form when retrieving from the database.
 */
public class AuthorizationGrantDataOptimizer extends AbstractSessionDataOptimizer {

    public static final String AUTHORIZATION_GRANT_OPTIMIZATION_ENABLED
            = "SessionDataOptimizationV2.AuthorizationGrant.Enable";
    public static final String LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED
            = "SessionDataOptimizationV2.AuthorizationGrant.OptimizeLocalUserAttributes";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    public static final Log LOG = LogFactory.getLog(AuthorizationGrantDataOptimizer.class);

    @Override
    public String getCacheName() {

        return "AuthorizationGrantCache";
    }

    @Override
    public boolean isOptimizationEnabled() {

        return getSessionDataOptimizationV2ConfigValue(AUTHORIZATION_GRANT_OPTIMIZATION_ENABLED);
    }

    @Override
    public Object optimizeSessionData(String key, Object entry) throws SessionDataOptimizationV2Exception {

        AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                new AuthorizationGrantCacheEntry((AuthorizationGrantCacheEntry) entry);

        if (isLocalUserAttributeOptimizationEnabled()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Local user attribute optimization is enabled. Optimizing local user attributes in " +
                        "AuthorizationGrantCacheEntry with key: " + key);
            }
            optimizeLocalUserAttributes(authorizationGrantCacheEntry, key);
            // resetLocalUserAttributes(authorizationGrantCacheEntry, key);
        }

        // logSessionDataIntoConsole(authorizationGrantCacheEntry);
        return authorizationGrantCacheEntry;
    }

    @Override
    public Object loadSessionData(String key, Object entry) throws SessionDataOptimizationV2Exception {

        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = (AuthorizationGrantCacheEntry) entry;

        if (isLocalUserAttributeOptimizationEnabled()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Local user attribute optimization is enabled. Restoring local user attributes in " +
                        "AuthorizationGrantCacheEntry with key: " + key);
            }
            resetLocalUserAttributes(authorizationGrantCacheEntry, key);
        }
        // logSessionDataIntoConsole(authorizationGrantCacheEntry);
        return authorizationGrantCacheEntry;
    }

    private void optimizeLocalUserAttributes(AuthorizationGrantCacheEntry entry, String keyId) {

        if (entry.getAuthenticatedUser() != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authenticated user found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Proceeding with optimization of local user attributes.");
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No authenticated user found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Skipping optimization of local user attributes.");
            }
            return;
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

        String[] claimURIList = getUserClaimURIsArray(entry.getUserAttributes());
        entry.setUserAttributesList(claimURIList);

        entry.setUserAttributes(filterRuntimeClaims(entry.getUserAttributes()));

        if  (LOG.isDebugEnabled()) {
            LOG.debug("Optimized local user attributes for authorization grant cache entry with key: " + keyId);
        }
    }

    private void resetLocalUserAttributes(AuthorizationGrantCacheEntry entry, String keyId)
            throws SessionDataOptimizationV2Exception {

        if (entry.getUserAttributesList() != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User attributes list found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Proceeding with restoration of local user attributes.");
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No user attributes list found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Skipping restoration of local user attributes.");
            }
            return;
        }

        AuthenticatedUser authenticatedUser = entry.getAuthenticatedUser();
        if (authenticatedUser.isFederatedUser()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Federated user found in AuthorizationGrantCacheEntry with key: " + keyId +
                        ". Skipping restoration of local user attributes.");
            }
            return;
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
        addMultiAttributeSeparatorToUserClaims(authenticatedUser, userAttributesMap);

        String[] claimsToResolve = entry.getUserAttributesList() != null
                ? entry.getUserAttributesList() : new String[0];
        if (claimsToResolve.length == 0) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No user attributes to restore for authorization grant cache entry with key: " + keyId);
            }
            concludeLocalAttributeOptimizationReset(entry, userAttributesMap, runtimeClaimURIs);
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
            concludeLocalAttributeOptimizationReset(entry, userAttributesMap, runtimeClaimURIs);
            return;
        }

        Map<String, String> carbonToStandardClaimMapping;
        try {
            carbonToStandardClaimMapping = ClaimMetadataHandler.getInstance()
                    .getMappingsMapFromOtherDialectToCarbon(OIDC_DIALECT, claimsToResolveSet,
                            authenticatedUser.getTenantDomain(), false);
        } catch (ClaimMetadataException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while retrieving claim mappings for OIDC dialect. User claims will not be " +
                        "applied to user claims in AuthorizationGrantCacheEntry with key: " + keyId, e);
            }
            concludeLocalAttributeOptimizationReset(entry, userAttributesMap, runtimeClaimURIs);
            return;
        }

        if (carbonToStandardClaimMapping.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No claim mappings found for OIDC dialect. User claims will not be applied to user " +
                        "claims in AuthorizationGrantCacheEntry with key: " + keyId);
            }
            concludeLocalAttributeOptimizationReset(entry, userAttributesMap, runtimeClaimURIs);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Continue resetting local user attributes from the user store for authorization grant " +
                    "cache entry with key: " + keyId);
        }

        Map<String, String> userClaimsFromUserStore =
                getUserClaimValues(authenticatedUser, carbonToStandardClaimMapping.values().toArray(new String[0]));

        for (String claimUri : claimsToResolveSet) {
            String localDialectClaimUri = carbonToStandardClaimMapping.get(claimUri);
            if (StringUtils.isEmpty(localDialectClaimUri)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No local claim mapping found for claim URI: " + claimUri + ". Skipping this claim.");
                }
                continue;
            }
            String claimValue = userClaimsFromUserStore.get(localDialectClaimUri);
            userAttributesMap.put(claimUri, claimValue);
        }

        if  (LOG.isDebugEnabled()) {
            LOG.debug("Completed retrieving local user attributes from the user store. Concluding the reset " +
                    "of local user attributes for authorization grant cache entry with key: " + keyId);
        }

        concludeLocalAttributeOptimizationReset(entry, userAttributesMap, runtimeClaimURIs);

        if  (LOG.isDebugEnabled()) {
            LOG.debug("Restored local user attributes for authorization grant cache entry with key: " + keyId);
        }
    }

    private void concludeLocalAttributeOptimizationReset(AuthorizationGrantCacheEntry entry,
                                                         Map<String, String> userAttributesMap,
                                                         Set<String> runtimeClaimURIs) {

        Map<ClaimMapping, String> finalClaimMappings = buildClaimMappings(userAttributesMap);
        finalClaimMappings.forEach((claimMapping, value) -> {
            if (runtimeClaimURIs.contains(claimMapping.getLocalClaim().getClaimUri())) {
                claimMapping.setIsRuntimeValue(true);
            }
        });
        entry.setUserAttributes(finalClaimMappings);
        entry.setUserAttributesList(null);
    }

    private boolean isLocalUserAttributeOptimizationEnabled() {

        return getSessionDataOptimizationV2ConfigValue(LOCAL_USER_ATTRIBUTE_OPTIMIZATION_ENABLED);
    }
}