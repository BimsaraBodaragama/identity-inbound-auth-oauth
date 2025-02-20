/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.rar.core;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.api.resource.mgt.APIResourceMgtException;
import org.wso2.carbon.identity.application.common.model.AuthorizationDetailsType;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A factory class to manage and provide instances of {@link AuthorizationDetailsProcessor} Service Provider Interface.
 * This class follows the Singleton pattern to ensure only one instance is created.
 * It uses {@link ServiceLoader} to dynamically load and manage {@link AuthorizationDetailsProcessor} implementations.
 * <p> Example usage:
 * <pre> {@code
 * // Get a specific provider by type
 * AuthorizationDetailsProcessorFactory.getInstance()
 *     .getAuthorizationDetailsProcessorByType("customer_information")
 *     .ifPresentOrElse(
 *         p -> log.debug("Provider for type " + type + ": " + p.getClass().getName()),
 *         () -> log.debug("No provider found for type " + type)
 *     );
 * } </pre> </p>
 *
 * @see AuthorizationDetailsProcessor AuthorizationDetailsService
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9396#name-request-parameter-authoriza">
 * Request Parameter "authorization_details"</a>
 */
public class AuthorizationDetailsProcessorFactory {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsProcessorFactory.class);
    private static volatile AuthorizationDetailsProcessorFactory instance;
    private final Map<String, AuthorizationDetailsProcessor> authorizationDetailsProcessors;

    /**
     * Private constructor to initialize the factory.
     * <p> This constructor is intentionally private to prevent direct instantiation of the
     * {@code AuthorizationDetailsProviderFactory} class.
     * Instead, use the {@link #getInstance()} method to obtain the singleton instance. </p>
     */
    private AuthorizationDetailsProcessorFactory() {

        this.authorizationDetailsProcessors = new HashMap<>();
    }

    /**
     * Provides the singleton instance of {@code AuthorizationDetailsProviderFactory}.
     *
     * @return Singleton instance of {@code AuthorizationDetailsProviderFactory}.
     */
    public static AuthorizationDetailsProcessorFactory getInstance() {

        if (instance == null) {
            synchronized (AuthorizationDetailsProcessorFactory.class) {
                if (instance == null) {
                    instance = new AuthorizationDetailsProcessorFactory();
                }
            }
        }
        return instance;
    }

    /**
     * Returns the {@link AuthorizationDetailsProcessor} provider for the given type.
     *
     * @param type A supported authorization details type.
     * @return {@link Optional} containing the {@link AuthorizationDetailsProcessor} if present, otherwise empty.
     * @see AuthorizationDetailsProcessor#getType() getAuthorizationDetailsType
     */
    public Optional<AuthorizationDetailsProcessor> getAuthorizationDetailsProcessorByType(final String type) {

        return Optional.ofNullable(this.authorizationDetailsProcessors.get(type));
    }

    /**
     * Checks if a given type has a valid service provider implementation.
     *
     * @param type The type to check.
     * @return {@code true} if the type is supported, {@code false} otherwise.
     * @see AuthorizationDetailsProcessor AuthorizationDetailsService
     */
    public boolean isSupportedAuthorizationDetailsType(final String type) {

        return this.getSupportedAuthorizationDetailTypes().contains(type);
    }

    /**
     * Returns an {@link Collections#unmodifiableSet} containing all supported authorization details types.
     * <p> A type is considered "supported" if it has been registered by invoking the
     * <code>POST: /api/server/v1/api-resources</code> endpoint. </p>
     *
     * @return An unmodifiable set of supported authorization details types.
     */
    public Set<String> getSupportedAuthorizationDetailTypes() {

        final String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {

            final List<AuthorizationDetailsType> authorizationDetailsTypes = OAuth2ServiceComponentHolder.getInstance()
                    .getAuthorizationDetailsTypeManager().getAuthorizationDetailsTypes(StringUtils.EMPTY, tenantDomain);

            if (authorizationDetailsTypes != null) {
                return authorizationDetailsTypes
                        .stream()
                        .map(AuthorizationDetailsType::getType)
                        .collect(Collectors.toUnmodifiableSet());
            }
        } catch (APIResourceMgtException e) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Error occurred while retrieving supported authorization details types " +
                        "for tenant: %s. Caused by, ", tenantDomain), e);
            }
        }
        return Collections.emptySet();
    }

    /**
     * Caches the provided {@link AuthorizationDetailsProcessor} instance by associating it with its corresponding
     * authorization details type. This allows efficient retrieval and reuse of processors based on their type.
     * <p> The type of the authorization details processor is obtained using
     * {@link AuthorizationDetailsProcessor#getType()}</p>
     *
     * @param authorizationDetailsProcessor Processor instance to be cached, keyed by its authorization details type.
     */
    public void setAuthorizationDetailsProcessors(final AuthorizationDetailsProcessor authorizationDetailsProcessor) {

        if (authorizationDetailsProcessor != null && StringUtils.isNotBlank(authorizationDetailsProcessor.getType())) {
            final String type = authorizationDetailsProcessor.getType();
            if (log.isDebugEnabled()) {
                log.debug(String.format("Registering AuthorizationDetailsProcessor %s against type %s",
                        authorizationDetailsProcessor.getClass().getSimpleName(), type));
            }
            this.authorizationDetailsProcessors.put(type, authorizationDetailsProcessor);
        }
    }
}
