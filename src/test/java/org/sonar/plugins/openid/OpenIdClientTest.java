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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegResponse;
import org.sonar.api.config.Settings;
import org.sonar.api.security.UserDetails;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
    thrown.expect(IllegalStateException.class);
    thrown.expectMessage("Property sonar.openid.sonarServerUrl is missing");

    OpenIdClient client = new OpenIdClient(new Settings());
    client.initReturnToUrl();
  }

  @Test
  public void initDiscoveryInfo_fail_if_missing_url() {
    thrown.expect(IllegalStateException.class);
    thrown.expectMessage("Property sonar.openid.providerUrl is missing");

    OpenIdClient client = new OpenIdClient(new Settings());
    client.start();
  }

  /**
   * Requires an internet connection
   */
  @Test
  public void initDiscoveryInfo_test_google() {
    Settings settings = new Settings()
        .setProperty(OpenIdClient.PROPERTY_SONAR_URL, "http://localhost:9000")
        .setProperty(OpenIdClient.PROPERTY_OPENID_URL, "https://www.google.com/o8/id");
    OpenIdClient client = new OpenIdClient(settings);
    client.start();

    assertThat(client.getDiscoveryInfo().getOPEndpoint().toString()).isEqualTo("https://www.google.com/o8/id");
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
  public void verify_failed_authentication() throws MessageException {
    OpenIdClient client = new OpenIdClient(mock(ConsumerManager.class));

    UserDetails user = client.verify("https://www.google.com/o8/id", ParameterList.createFromQueryString(""));

    assertThat(user).isNull();
  }
}
