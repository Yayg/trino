/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.server.security.oauth2;

import com.google.common.collect.ImmutableMap;
import io.trino.server.security.UserMappingException;
import io.trino.spi.security.Identity;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class TestOAuth2Authenticator
{
    private static final String TOKEN = "test-token";

    @Test
    public void testGroupsFieldNotConfigured()
            throws UserMappingException
    {
        Identity identity = authenticate(new OAuth2Config(), claims("groups", List.of("radiologie", "cardiologie")));
        assertThat(identity.getGroups()).isEmpty();
    }

    @Test
    public void testGroupsClaimMissing()
            throws UserMappingException
    {
        Identity identity = authenticate(configWithGroupsField(), claims());
        assertThat(identity.getGroups()).isEmpty();
    }

    @Test
    public void testGroupsClaimAsListOfStrings()
            throws UserMappingException
    {
        Identity identity = authenticate(configWithGroupsField(), claims("groups", List.of("radiologie", "cardiologie")));
        assertThat(identity.getGroups()).containsExactlyInAnyOrder("radiologie", "cardiologie");
    }

    @Test
    public void testGroupsClaimAsSingleString()
            throws UserMappingException
    {
        Identity identity = authenticate(configWithGroupsField(), claims("groups", "radiologie"));
        assertThat(identity.getGroups()).containsExactly("radiologie");
    }

    @Test
    public void testGroupsClaimWithInvalidType()
            throws UserMappingException
    {
        Identity identity = authenticate(configWithGroupsField(), claims("groups", 42));
        assertThat(identity.getGroups()).isEmpty();
    }

    @Test
    public void testGroupsClaimListWithInvalidElement()
            throws UserMappingException
    {
        Identity identity = authenticate(configWithGroupsField(), claims("groups", List.of("radiologie", 42)));
        assertThat(identity.getGroups()).isEmpty();
    }

    private static Map<String, Object> claims(Object... nameValuePairs)
    {
        ImmutableMap.Builder<String, Object> claims = ImmutableMap.builder();
        claims.put("sub", "alice");
        for (int i = 0; i < nameValuePairs.length; i += 2) {
            claims.put((String) nameValuePairs[i], nameValuePairs[i + 1]);
        }
        return claims.buildOrThrow();
    }

    private static OAuth2Config configWithGroupsField()
    {
        return new OAuth2Config().setGroupsField("groups");
    }

    private static Identity authenticate(OAuth2Config config, Map<String, Object> claims)
            throws UserMappingException
    {
        OAuth2Client client = new TestingOAuth2Client(claims);
        OAuth2Authenticator authenticator = new OAuth2Authenticator(
                client,
                config,
                new TokenRefresher(TokenPairSerializer.ACCESS_TOKEN_ONLY_SERIALIZER, new TestingOAuth2TokenHandler(), client),
                TokenPairSerializer.ACCESS_TOKEN_ONLY_SERIALIZER);
        return authenticator.createIdentity(TOKEN).orElseThrow();
    }

    private static class TestingOAuth2Client
            implements OAuth2Client
    {
        private final Map<String, Object> claims;

        TestingOAuth2Client(Map<String, Object> claims)
        {
            this.claims = claims;
        }

        @Override
        public void load() {}

        @Override
        public Request createAuthorizationRequest(String state, URI callbackUri)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public Response getOAuth2Response(String code, URI callbackUri, Optional<String> nonce)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<Map<String, Object>> getAccessTokenClaims(String accessToken)
        {
            return Optional.of(claims);
        }

        @Override
        public Response refreshTokens(String refreshToken)
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<URI> getLogoutEndpoint(Optional<String> idToken, URI callbackUrl)
        {
            throw new UnsupportedOperationException();
        }
    }

    private static class TestingOAuth2TokenHandler
            implements OAuth2TokenHandler
    {
        @Override
        public void setAccessToken(String hashedState, String accessToken) {}

        @Override
        public void setTokenExchangeError(String hashedState, String errorMessage) {}
    }
}
