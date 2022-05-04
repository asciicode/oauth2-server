package nz.co.logicons.tlp.oauth2.authserver.conf;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.encoding.PasswordEncoder;

/**
 * @author Allen
 *
 */
@SuppressWarnings("deprecation")
public class TLPPasswordEncoder
    implements
    PasswordEncoder
{

  @Override
  public String encodePassword(String rawPass, Object salt)
  {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public boolean isPasswordValid(String encPass, String rawPass, Object salt)
  {
    if (salt == null)
    {
      return false;
    }
    String hashes = createHash(rawPass, salt.toString());
    // System.out.println(encPass + "========" + hashes);
    return StringUtils.equals(encPass, hashes);
  }

  /**
   * Hash input with salt.
   */
  private String createHash(String input, String salt)
  {
    return DigestUtils.sha256Hex(salt + input);
  }

}
