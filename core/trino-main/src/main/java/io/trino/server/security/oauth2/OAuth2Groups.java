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

import com.google.common.collect.ImmutableSet;
import io.airlift.log.Logger;

import java.util.List;
import java.util.Set;

public final class OAuth2Groups
{
    private static final Logger log = Logger.get(OAuth2Groups.class);

    private OAuth2Groups() {}

    public static Set<String> extractGroups(Object claimValue, String fieldName)
    {
        if (claimValue == null) {
            return ImmutableSet.of();
        }
        if (claimValue instanceof String value) {
            return ImmutableSet.of(value);
        }
        if (claimValue instanceof List<?> values) {
            ImmutableSet.Builder<String> groups = ImmutableSet.builder();
            for (Object value : values) {
                if (!(value instanceof String stringValue)) {
                    log.warn("Ignoring groups claim '%s': expected a list of strings, but element %s is a %s", fieldName, value, value.getClass().getSimpleName());
                    return ImmutableSet.of();
                }
                groups.add(stringValue);
            }
            return groups.build();
        }
        log.warn("Ignoring groups claim '%s': expected a string or a list of strings, but got a %s", fieldName, claimValue.getClass().getSimpleName());
        return ImmutableSet.of();
    }
}
