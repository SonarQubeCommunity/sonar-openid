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
import org.sonar.api.config.Settings;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

public class OpenIdLogoutFilterTest {

  @Test
  public void url_pattern() {
    OpenIdLogoutFilter filter = new OpenIdLogoutFilter(new Settings());

    assertThat(filter.doGetPattern().toString()).isEqualTo("/sessions/logout");
  }

  @Test
  public void log_logout_at_startup() throws Exception {
    Settings settings = new Settings().setProperty(OpenIdLogoutFilter.PROPERTY_PROVIDER_LOGOUT_URL, "https://www.google.com/accounts/Logout");
    OpenIdLogoutFilter filter = new OpenIdLogoutFilter(settings);
    filter.init(mock(FilterConfig.class));

    // oh well, hard to test logs, but at least we check that it does not fail
  }

  @Test
  public void should_not_redirect_if_no_logout_url() throws Exception {
    Settings settings = new Settings();
    OpenIdLogoutFilter filter = new OpenIdLogoutFilter(settings);

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
    verify(response, never()).sendRedirect(anyString());
  }

  @Test
  public void should_redirect_to_provider_logout_url() throws Exception {
    Settings settings = new Settings().setProperty(OpenIdLogoutFilter.PROPERTY_PROVIDER_LOGOUT_URL, "https://www.google.com/accounts/Logout");
    OpenIdLogoutFilter filter = new OpenIdLogoutFilter(settings);

    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
    verify(response).sendRedirect("https://www.google.com/accounts/Logout");
  }
}
