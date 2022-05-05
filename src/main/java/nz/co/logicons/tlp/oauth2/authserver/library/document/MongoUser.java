package nz.co.logicons.tlp.oauth2.authserver.library.document;

import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "user")
public class MongoUser {

    @Id
    private String id;

    private String username;
    private String password;

    private String passwordhash;
    private String passwordsalt;
    private Set<String> roles;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public String getPasswordsalt()
    {
      return passwordsalt;
    }

    public void setPasswordsalt(String passwordsalt)
    {
      this.passwordsalt = passwordsalt;
    }

    public String getPasswordhash()
    {
      return passwordhash;
    }

    public void setPasswordhash(String passwordhash)
    {
      this.passwordhash = passwordhash;
    }
}