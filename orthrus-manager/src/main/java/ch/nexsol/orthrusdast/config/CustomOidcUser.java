package ch.nexsol.orthrusdast.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.util.Collection;
import java.util.Map;

public class CustomOidcUser extends DefaultOidcUser {

    private final Map<String, Object> accessTokenAttributes;

    public CustomOidcUser(Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken, OidcUserInfo userInfo, Map<String, Object> accessTokenAttributes) {
        super(authorities, idToken, userInfo);
        this.accessTokenAttributes = accessTokenAttributes;
    }

    @Override
    public String getName() {
        // Try preferred_username from standard attributes
        if (getAttributes().containsKey("preferred_username")) {
            return getAttributes().get("preferred_username").toString();
        }
        // Try from access token
        if (accessTokenAttributes != null && accessTokenAttributes.containsKey("preferred_username")) {
            return accessTokenAttributes.get("preferred_username").toString();
        }
        // Fallback to name
        if (getAttributes().containsKey("name")) {
            return getAttributes().get("name").toString();
        }
        // Fallback to super (which is sub)
        return super.getName();
    }
    
    @Override
    public Map<String, Object> getAttributes() {
        Map<String, Object> attrs = new java.util.HashMap<>(super.getAttributes());
        if (accessTokenAttributes != null) {
            attrs.putAll(accessTokenAttributes);
        }
        return attrs;
    }
}
