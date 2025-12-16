package in.troyza.commonAuth.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.jwt")
public class JwtProperties {
    private String secret;
    private int expirationMs;
    private String cookieName;

    // getters and setters
    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }

    public int getExpirationMs() { return expirationMs; }
    public void setExpirationMs(int expirationMs) { this.expirationMs = expirationMs; }

    public String getCookieName() { return cookieName; }
    public void setCookieName(String cookieName) { this.cookieName = cookieName; }
}

