package nz.co.logicons.tlp.oauth2.authserver.conf;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 * @author Allen
 *
 */
public class User
    extends org.springframework.security.core.userdetails.User
{
  private String passwordsalt;
  private static final long serialVersionUID = 1L;

  public User(String username, String password, boolean enabled, boolean accountNonExpired,
    boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities)
  {
    super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
  }

  public User(String username, String password, Collection<? extends GrantedAuthority> authorities)
  {
    super(username, password, authorities);
  }

  public String getPasswordsalt()
  {
    return passwordsalt;
  }

  public void setPasswordsalt(String passwordsalt)
  {
    this.passwordsalt = passwordsalt;
  }

}
