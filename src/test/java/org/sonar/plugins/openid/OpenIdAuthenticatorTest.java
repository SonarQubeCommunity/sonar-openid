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

import org.junit.Test;
import org.sonar.api.security.Authenticator;
import org.sonar.api.security.UserDetails;

import javax.servlet.http.HttpServletRequest;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpenIdAuthenticatorTest {

  @Test
  public void doAuthenticate_success() {
    OpenIdAuthenticator authenticator = new OpenIdAuthenticator();
    HttpServletRequest request = mock(HttpServletRequest.class);
    UserDetails user = new UserDetails();
    user.setName("rick");
    when(request.getAttribute(OpenIdValidationFilter.USER_ATTRIBUTE)).thenReturn(user);
    Authenticator.Context context = new Authenticator.Context(null, null, request);

    assertThat(authenticator.doAuthenticate(context)).isTrue();
  }

  @Test
  public void doAuthenticate_failure_if_missing_name() {
    OpenIdAuthenticator authenticator = new OpenIdAuthenticator();
    HttpServletRequest request = mock(HttpServletRequest.class);
    UserDetails user = new UserDetails(); // no name
    when(request.getAttribute(OpenIdValidationFilter.USER_ATTRIBUTE)).thenReturn(user);
    Authenticator.Context context = new Authenticator.Context(null, null, request);

    assertThat(authenticator.doAuthenticate(context)).isFalse();
  }

  @Test
  public void doAuthenticate_failure() {
    OpenIdAuthenticator authenticator = new OpenIdAuthenticator();
    Authenticator.Context context = new Authenticator.Context(null, null, mock(HttpServletRequest.class));

    assertThat(authenticator.doAuthenticate(context)).isFalse();
  }
}
