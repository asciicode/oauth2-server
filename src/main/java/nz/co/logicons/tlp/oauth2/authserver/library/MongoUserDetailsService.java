package nz.co.logicons.tlp.oauth2.authserver.library;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import nz.co.logicons.tlp.core.genericmodels.nodes.DocumentNode;
import nz.co.logicons.tlp.core.genericmodels.permissions.Role;
import nz.co.logicons.tlp.core.mongo.MongoDatastore;
import nz.co.logicons.tlp.oauth2.authserver.conf.User;

/**
 * @author Allen
 *
 */
public class MongoUserDetailsService implements UserDetailsService {

    @Autowired
    private MongoDatastore datastore;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
      // Query query = new Query();
      // query.addCriteria(Criteria.where("username").is(username));
      // MongoUser user =
      // mongoTemplate.findOne(query, MongoUser.class);
      // if (user == null) {
      // throw new UsernameNotFoundException(String.format("Username %s not found", username));
      // }

      // DocumentSchema userSchema = datastore.getSchema("(user)");
      // String userJson = datastore.get("(user)", username, false);
      // if (StringUtils.isBlank(userJson))
      // {
      // throw new UsernameNotFoundException(String.format("Username %s not found", username));
      // }
      // DocumentNode docNode = transformOperation.createDocumentNode(userJson, userSchema);
      DocumentNode docNode = datastore.getDocument(nz.co.logicons.tlp.core.business.models.User.SCHEMA, username,
          false);
      if (docNode == null)
      {
        throw new UsernameNotFoundException(String.format("Username %s not found", username));
      }
        System.out.println(docNode.prettyPrintDocumentValues());
        nz.co.logicons.tlp.core.business.models.User user = new nz.co.logicons.tlp.core.business.models.User(docNode);
        List<Role> roleList = user.getRoles().getRoles();
        List<String> rolez = new ArrayList<>();
        for (Role tmp : roleList) {
          rolez.add(tmp.getId());
        }
        String[] roles = new String[roleList.size()];
        // List<SimpleGrantedAuthority> sgAuth = AuthorityUtils.createAuthorityList(rolez.toArray(roles));
        User userLocal = new User(user.getId(), user.getPasswordHash(),
            AuthorityUtils.createAuthorityList(rolez.toArray(roles)));
        userLocal.setPasswordsalt(user.getPasswordSalt());
        return userLocal;
    }
}