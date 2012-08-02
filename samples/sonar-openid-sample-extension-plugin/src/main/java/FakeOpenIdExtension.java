import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.sonar.plugins.openid.api.OpenIdExtension;

public class FakeOpenIdExtension extends OpenIdExtension {

  @Override
  public void doOnRequest(AuthRequest authReq) {
    // add Sreg or AX attributes to authReq
  }

  @Override
  public boolean doVerifyResponse(AuthSuccess response) {
    // verify some conditions
    return true;
  }
}
