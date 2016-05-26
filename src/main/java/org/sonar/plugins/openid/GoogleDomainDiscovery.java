package org.sonar.plugins.openid;

import org.openid4java.discovery.Discovery;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.discovery.UrlIdentifier;

import java.util.ArrayList;
import java.util.List;

/**
 * Code below adapted from Jenkins OpenID plugin at
 * https://github.com/jenkinsci/openid-plugin/blob/master/src/main/java/hudson/plugins/openid/GoogleAppSsoSecurityRealm.java
 * 
 * Original authors Kohsuke Kawaguchi and Stephen Connoly
 * 
 * @author Nick Spacek
 *
 */
public class GoogleDomainDiscovery extends Discovery {
  private String domain;

  public GoogleDomainDiscovery(String domain) {
    super();
    this.domain = domain;
  }
  
  @Override
  public List discover(Identifier id) throws DiscoveryException {
    if (id.getIdentifier().startsWith("http://" + domain + '/') && id instanceof UrlIdentifier) {
      String source = "https://www.google.com/accounts/o8/user-xrds?uri=" + id.getIdentifier();
      List<DiscoveryInformation> r = super.discover(new UrlIdentifier(source));
      List<DiscoveryInformation> x = new ArrayList<DiscoveryInformation>();
      for (DiscoveryInformation discovered : r) {
        if (discovered.getClaimedIdentifier().getIdentifier().equals(source)) {
          discovered = new DiscoveryInformation(discovered.getOPEndpoint(),
            id,
            discovered.getDelegateIdentifier(),
            discovered.getVersion(),
            discovered.getTypes()
          );
        }
        x.add(discovered);
      }
      return x;
    }
    return super.discover(id);
  }
}
