/*
 * Sonar OpenID Plugin
 * Copyright (C) 2012 SonarSource
 * dev@sonar.codehaus.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package org.sonar.plugins.openid;

import com.google.common.collect.Lists;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.UrlIdentifier;
import org.openid4java.message.*;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegResponse;
import org.sonar.api.config.Settings;
import org.sonar.api.security.UserDetails;
import org.sonar.plugins.openid.api.OpenIdExtension;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

public class OpenIdClientTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void initReturnUrl() {
    Settings settings = new Settings().setProperty(OpenIdClient.PROPERTY_SONAR_URL, "http://localhost:9000");
    OpenIdClient client = new OpenIdClient(settings);
    client.initReturnToUrl();

    assertThat(client.getReturnToUrl()).isEqualTo("http://localhost:9000/openid/validate");
  }

  @Test
  public void initReturnUrl_fail_if_missing_sonar_url() {
    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("Property sonar.openid.sonarServerUrl is missing");

    OpenIdClient client = new OpenIdClient(new Settings());
    client.initReturnToUrl();
  }

  @Test
  public void initDiscoveryInfo_fail_if_missing_url_and_domain() {
    thrown.expect(IllegalStateException.class);
    thrown.expectMessage("Property sonar.openid.providerUrl is missing");

    OpenIdClient client = new OpenIdClient(new Settings());
    client.start();
  }
  
  @Test
  public void initDiscoveryInfo_succeed_if_domain_specified() {
    Settings settings = new Settings().setProperty(OpenIdClient.PROPERTY_SONAR_URL, "http://localhost:9000")
        .setProperty(OpenIdClient.PROPERTY_OPENID_GOOGLE_DOMAIN, "lashpoint.com");

    OpenIdClient client = new OpenIdClient(settings);
    client.start();
  }

  /**
   * TODO Currently requires an internet connection. An OpenId server should be embedded.
   * Meanwhile the test connects to Google, and if it's down (yes it's possible !), the test fallbacks on Yahoo.
   */
  @Test
  public void initDiscoveryInfo_test_google() {
    try {
      testRemoteOpenIdProvider("https://www.google.com/o8/id");
    } catch (Exception e) {
      System.out.println("Failed to connect to Google OpenId Provider");
      e.printStackTrace();
      testRemoteOpenIdProvider("http://open.login.yahoo.com");
    }
  }

  private void testRemoteOpenIdProvider(String endpoint) {
    Settings settings = new Settings()
      .setProperty(OpenIdClient.PROPERTY_SONAR_URL, "http://localhost:9000")
      .setProperty(OpenIdClient.PROPERTY_OPENID_URL, endpoint);
    OpenIdClient client = new OpenIdClient(settings);
    client.start();

    assertThat(client.getDiscoveryInfo().getOPEndpoint().toString()).isEqualTo(endpoint);
    assertThat(client.getDiscoveryInfo().getVersion()).startsWith("http://");
  }

  @Test
  public void initDiscoveryInfo_fail_if_bad_provider() {
    thrown.expect(IllegalStateException.class);
    thrown.expectMessage("Fail to discover OpenID endpoint: abc is not xyz");

    Settings settings = new Settings()
      .setProperty(OpenIdClient.PROPERTY_SONAR_URL, "http://localhost:9000")
      .setProperty(OpenIdClient.PROPERTY_OPENID_URL, "abc is not xyz");
    OpenIdClient client = new OpenIdClient(settings);
    client.start();
  }

  @Test
  public void toUserDetails_null_if_missing_name() throws Exception {
    AuthSuccess authSuccess = mock(AuthSuccess.class);
    UserDetails user = OpenIdClient.toUser(authSuccess);
    assertThat(user).isNull();
  }

  @Test
  public void toUserDetails_sreg_attributes() throws Exception {
    AuthSuccess authSuccess = mock(AuthSuccess.class);
    when(authSuccess.hasExtension(SRegMessage.OPENID_NS_SREG)).thenReturn(true);
    SRegResponse sreg = SRegResponse.createFetchResponse();
    sreg.addAttribute("fullname", "me");
    sreg.addAttribute("email", "me@here.com");
    when(authSuccess.getExtension(SRegMessage.OPENID_NS_SREG)).thenReturn(sreg);

    UserDetails user = OpenIdClient.toUser(authSuccess);

    assertThat(user.getName()).isEqualTo("me");
    assertThat(user.getEmail()).isEqualTo("me@here.com");
  }

  @Test
  public void toUserDetails_missing_fields() throws Exception {
    AuthSuccess authSuccess = mock(AuthSuccess.class);
    when(authSuccess.hasExtension(SRegMessage.OPENID_NS_SREG)).thenReturn(true);
    SRegResponse sreg = SRegResponse.createFetchResponse();
    when(authSuccess.getExtension(SRegMessage.OPENID_NS_SREG)).thenReturn(sreg);

    UserDetails user = OpenIdClient.toUser(authSuccess);

    assertThat(user).isNull();
  }

  @Test
  public void toUserDetails_ax_attributes() throws Exception {
    AuthSuccess authSuccess = mock(AuthSuccess.class);
    when(authSuccess.hasExtension(AxMessage.OPENID_NS_AX)).thenReturn(true);
    FetchResponse ax = FetchResponse.createFetchResponse();
    ax.addAttribute("firstName", "spec_type", "Rick");
    ax.addAttribute("lastName", "spec_type", "Hunter");
    ax.addAttribute("email", "spec_type", "rick@hunter.com");
    when(authSuccess.getExtension(AxMessage.OPENID_NS_AX)).thenReturn(ax);

    UserDetails user = OpenIdClient.toUser(authSuccess);

    assertThat(user.getName()).isEqualTo("Rick Hunter");
    assertThat(user.getEmail()).isEqualTo("rick@hunter.com");
  }

  @Test
  public void should_ignore_auth_cancellation() throws Exception {
    ConsumerManager consumerManager = mock(ConsumerManager.class);

    // no "verifiedId", for example when user does not approve to send Google profile (the form after authentication)
    VerificationResult verification = new VerificationResult();
    verification.setVerifiedId(null);

    when(consumerManager.verify(anyString(), any(ParameterList.class), any(DiscoveryInformation.class))).thenReturn(verification);
    OpenIdClient client = new OpenIdClient(new Settings()).setConsumerManager(consumerManager);

    UserDetails user = client.verify("http://localhost:9000", new ParameterList());
    assertThat(user).isNull();
  }

  @Test
  public void createAuthenticationRequest() throws Exception {
    ConsumerManager consumerManager = mock(ConsumerManager.class);
    AuthRequest request = mock(AuthRequest.class);
    when(consumerManager.authenticate(any(DiscoveryInformation.class), anyString())).thenReturn(request);

    AuthRequest result = new OpenIdClient(new Settings()).setConsumerManager(consumerManager).createAuthenticationRequest();

    assertThat(result).isSameAs(request);
    verify(request, times(2)).addExtension(any(MessageExtension.class));
  }

  @Test
  public void createAuthenticationRequest_fail() throws Exception {
    thrown.expect(IllegalStateException.class);

    ConsumerManager consumerManager = mock(ConsumerManager.class);
    when(consumerManager.authenticate(any(DiscoveryInformation.class), anyString())).thenThrow(new ConsumerException(""));

    new OpenIdClient(new Settings()).setConsumerManager(consumerManager).createAuthenticationRequest();
  }

  @Test
  public void unauthorized_by_extension() throws Exception {
    ConsumerManager consumerManager = mock(ConsumerManager.class);

    VerificationResult result = newAuthenticatedResult();
    when(consumerManager.verify(eq("http://localhost:9000"), any(ParameterList.class), any(DiscoveryInformation.class)))
      .thenReturn(result);

    OpenIdClient client = new OpenIdClient(new Settings(), Lists.<OpenIdExtension>newArrayList(new UnauthorizeExtension(), new AuthorizeExtension()));
    client.setConsumerManager(consumerManager);

    assertThat(client.verify("http://localhost:9000", new ParameterList())).isNull();
  }

  @Test
  public void authorized_by_extensions() throws Exception {
    ConsumerManager consumerManager = mock(ConsumerManager.class);

    VerificationResult result = newAuthenticatedResult();
    when(consumerManager.verify(eq("http://localhost:9000"), any(ParameterList.class), any(DiscoveryInformation.class)))
      .thenReturn(result);

    OpenIdClient client = new OpenIdClient(new Settings(), Lists.<OpenIdExtension>newArrayList(new AuthorizeExtension()));
    client.setConsumerManager(consumerManager);

    assertThat(client.verify("http://localhost:9000", new ParameterList())).isNotNull();
  }

  private VerificationResult newAuthenticatedResult() throws DiscoveryException, MessageException {
    VerificationResult verification = new VerificationResult();
    verification.setVerifiedId(new UrlIdentifier("http://example.com"));
    SRegResponse sRegResponse = SRegResponse.createSRegResponse(new ParameterList());
    sRegResponse.addAttribute(OpenIdClient.SREG_ATTR_FULLNAME, "marius");
    AuthSuccess authSuccess = mock(AuthSuccess.class);
    when(authSuccess.hasExtension(SRegMessage.OPENID_NS_SREG)).thenReturn(true);
    when(authSuccess.getExtension(SRegMessage.OPENID_NS_SREG)).thenReturn(sRegResponse);
    verification.setAuthResponse(authSuccess);
    return verification;
  }

  static class AuthorizeExtension extends OpenIdExtension {
    @Override
    public boolean doVerifyResponse(AuthSuccess response) {
      return true;
    }
  }

  static class UnauthorizeExtension extends OpenIdExtension {
    @Override
    public boolean doVerifyResponse(AuthSuccess response) {
      return false;
    }
  }
}
