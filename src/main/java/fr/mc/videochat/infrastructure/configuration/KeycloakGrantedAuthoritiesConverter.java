package fr.mc.videochat.infrastructure.configuration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;

public class KeycloakGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        private final Log logger = LogFactory.getLog(this.getClass());
        private static final Collection<String> WELL_KNOWN_AUTHORITIES_CLAIM_NAMES = Arrays.asList("scope", "scp");
        private String authorityPrefix = "SCOPE_";
        private String rolePrefix = "ROLE_";
        private String authoritiesClaimName;

        public KeycloakGrantedAuthoritiesConverter() {
        }

        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList();
            Iterator var3 = this.getAuthorities(jwt).iterator();

            while(var3.hasNext()) {
                String authority = (String)var3.next();
                grantedAuthorities.add(new SimpleGrantedAuthority(this.authorityPrefix + authority));
            }

            return grantedAuthorities;
        }

        public void setAuthorityPrefix(String authorityPrefix) {
            Assert.notNull(authorityPrefix, "authorityPrefix cannot be null");
            this.authorityPrefix = authorityPrefix;
        }

        public void setAuthoritiesClaimName(String authoritiesClaimName) {
            Assert.hasText(authoritiesClaimName, "authoritiesClaimName cannot be empty");
            this.authoritiesClaimName = authoritiesClaimName;
        }

        private String getAuthoritiesClaimName(Jwt jwt) {
            if (this.authoritiesClaimName != null) {
                return this.authoritiesClaimName;
            } else {
                Iterator var2 = WELL_KNOWN_AUTHORITIES_CLAIM_NAMES.iterator();

                String claimName;
                do {
                    if (!var2.hasNext()) {
                        return null;
                    }

                    claimName = (String)var2.next();
                } while(!jwt.hasClaim(claimName));

                return claimName;
            }
        }

        private Collection<String> getAuthorities(Jwt jwt) {
            String claimName = this.getAuthoritiesClaimName(jwt);
            if (claimName == null) {
                this.logger.trace("Returning no authorities since could not find any claims that might contain scopes");
                return Collections.emptyList();
            } else {
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace(LogMessage.format("Looking for scopes in claim %s", claimName));
                }

                Object authorities = jwt.getClaim(claimName);
                if (authorities instanceof String) {
                    return StringUtils.hasText((String)authorities) ? Arrays.asList(((String)authorities).split(" ")) : Collections.emptyList();
                } else {
                    return (Collection)(authorities instanceof Collection ? this.castAuthoritiesToCollection(authorities) : Collections.emptyList());
                }
            }
        }

        private Collection<String> castAuthoritiesToCollection(Object authorities) {
            return (Collection)authorities;
        }
    }