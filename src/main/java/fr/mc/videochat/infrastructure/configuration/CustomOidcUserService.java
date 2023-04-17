package fr.mc.videochat.infrastructure.configuration;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.*;
import java.util.function.Function;

public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
    private static final Converter<Map<String, Object>, Map<String, Object>> DEFAULT_CLAIM_TYPE_CONVERTER = new ClaimTypeConverter(createDefaultClaimTypeConverters());
    private Set<String> accessibleScopes = new HashSet(Arrays.asList("profile", "email", "address", "phone"));
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = new DefaultOAuth2UserService();
    private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory = (clientRegistration) -> {
        return DEFAULT_CLAIM_TYPE_CONVERTER;
    };

    public CustomOidcUserService() {
    }

    public static Map<String, Converter<Object, ?>> createDefaultClaimTypeConverters() {
        Converter<Object, ?> booleanConverter = getConverter(TypeDescriptor.valueOf(Boolean.class));
        Converter<Object, ?> instantConverter = getConverter(TypeDescriptor.valueOf(Instant.class));
        Map<String, Converter<Object, ?>> claimTypeConverters = new HashMap();
        claimTypeConverters.put("email_verified", booleanConverter);
        claimTypeConverters.put("phone_number_verified", booleanConverter);
        claimTypeConverters.put("updated_at", instantConverter);
        return claimTypeConverters;
    }

    private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
        TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
        return (source) -> {
            return ClaimConversionService.getSharedInstance().convert(source, sourceDescriptor, targetDescriptor);
        };
    }

    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");
        OidcUserInfo userInfo = null;
        if (this.shouldRetrieveUserInfo(userRequest)) {
            OAuth2User oauth2User = this.oauth2UserService.loadUser(userRequest);
            Map<String, Object> claims = this.getClaims(userRequest, oauth2User);
            userInfo = new OidcUserInfo(claims);
            OAuth2Error oauth2Error;
            if (userInfo.getSubject() == null) {
                oauth2Error = new OAuth2Error("invalid_user_info_response");
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }

            if (!userInfo.getSubject().equals(userRequest.getIdToken().getSubject())) {
                oauth2Error = new OAuth2Error("invalid_user_info_response");
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet();
        authorities.add(new OidcUserAuthority(userRequest.getIdToken(), userInfo));
        OAuth2AccessToken token = userRequest.getAccessToken();
        Iterator scopesIterator = token.getScopes().iterator();

        while(scopesIterator.hasNext()) {
            String authority = (String)scopesIterator.next();
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
        }

        Object resourceAccessClam = userRequest.getIdToken().getClaim("resource_access");
        if(resourceAccessClam instanceof Map<?,?>){
            List roles = (List) ((Map) ((Map) resourceAccessClam).get("videochat")).get("roles");
            Iterator rolesIterator = roles.iterator();

            while(rolesIterator.hasNext()) {
                String authority = (String)rolesIterator.next();
                authorities.add(new SimpleGrantedAuthority("ROLE_" + authority));
            }
        }


        return this.getUser(userRequest, userInfo, authorities);
    }

    private Map<String, Object> getClaims(OidcUserRequest userRequest, OAuth2User oauth2User) {
        Converter<Map<String, Object>, Map<String, Object>> converter = (Converter)this.claimTypeConverterFactory.apply(userRequest.getClientRegistration());
        return converter != null ? (Map)converter.convert(oauth2User.getAttributes()) : (Map)DEFAULT_CLAIM_TYPE_CONVERTER.convert(oauth2User.getAttributes());
    }

    private OidcUser getUser(OidcUserRequest userRequest, OidcUserInfo userInfo, Set<GrantedAuthority> authorities) {
        ClientRegistration.ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
        String userNameAttributeName = providerDetails.getUserInfoEndpoint().getUserNameAttributeName();
        return StringUtils.hasText(userNameAttributeName) ? new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo, userNameAttributeName) : new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
    }

    private boolean shouldRetrieveUserInfo(OidcUserRequest userRequest) {
        ClientRegistration.ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
        if (StringUtils.isEmpty(providerDetails.getUserInfoEndpoint().getUri())) {
            return false;
        } else if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(userRequest.getClientRegistration().getAuthorizationGrantType())) {
            return false;
        } else {
            return this.accessibleScopes.isEmpty() || CollectionUtils.isEmpty(userRequest.getAccessToken().getScopes()) || CollectionUtils.containsAny(userRequest.getAccessToken().getScopes(), this.accessibleScopes);
        }
    }

    public final void setOauth2UserService(OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
        Assert.notNull(oauth2UserService, "oauth2UserService cannot be null");
        this.oauth2UserService = oauth2UserService;
    }

    public final void setClaimTypeConverterFactory(Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory) {
        Assert.notNull(claimTypeConverterFactory, "claimTypeConverterFactory cannot be null");
        this.claimTypeConverterFactory = claimTypeConverterFactory;
    }

    public final void setAccessibleScopes(Set<String> accessibleScopes) {
        Assert.notNull(accessibleScopes, "accessibleScopes cannot be null");
        this.accessibleScopes = accessibleScopes;
    }
}