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
import org.openid4java.message.ParameterList;
import org.sonar.api.security.UserDetails;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class OpenIdValidationFilterTest {
  @Test
  public void should_verify_and_continue_chaining() throws Exception {
    OpenIdClient openIdClient = mock(OpenIdClient.class);
    when(openIdClient.verify(anyString(), any(ParameterList.class))).thenReturn(null);
    when(openIdClient.getReturnToUrl()).thenReturn("http://localhost:9000");

    OpenIdValidationFilter filter = new OpenIdValidationFilter(openIdClient);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:9000?foo=bar"));
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    // not authenticated
    verify(request, never()).setAttribute(anyString(), anyObject());

    verify(openIdClient).verify(eq("http://localhost:9000?foo=bar"), any(ParameterList.class));
    verify(chain).doFilter(request, response);
    verifyZeroInteractions(response);
  }

  @Test
  public void should_support_ssl() throws Exception {
    OpenIdClient openIdClient = mock(OpenIdClient.class);
    when(openIdClient.verify(anyString(), any(ParameterList.class))).thenReturn(null);
    when(openIdClient.getReturnToUrl()).thenReturn("https://localhost:9000");

    OpenIdValidationFilter filter = new OpenIdValidationFilter(openIdClient);
    HttpServletRequest request = mock(HttpServletRequest.class);
    // return http instead of https when a proxy is installed
    when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:9000?foo=bar"));
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    // not authenticated
    verify(request, never()).setAttribute(anyString(), anyObject());

    verify(openIdClient).verify(eq("https://localhost:9000?foo=bar"), any(ParameterList.class));
    verify(chain).doFilter(request, response);
    verifyZeroInteractions(response);
  }

  @Test
  public void doGetPattern() {
    OpenIdValidationFilter filter = new OpenIdValidationFilter(mock(OpenIdClient.class));

    assertThat(filter.doGetPattern().toString()).isEqualTo("/openid/validate");
  }

  @Test
  public void init_and_destroy_do_nothing() throws ServletException {
    OpenIdValidationFilter filter = new OpenIdValidationFilter(mock(OpenIdClient.class));

    filter.init(mock(FilterConfig.class));
    filter.destroy();

    // oh well... what can be tested ??
  }

  @Test
  public void add_user_to_session_on_successful_authentication() throws Exception {
    OpenIdClient openIdClient = mock(OpenIdClient.class);
    UserDetails user = new UserDetails();
    when(openIdClient.verify(anyString(), any(ParameterList.class))).thenReturn(user);

    OpenIdValidationFilter filter = new OpenIdValidationFilter(openIdClient);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRequestURL()).thenReturn(new StringBuffer("http://www.google.com/o8/id"));
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    // user is added to HTTP request
    verify(request).setAttribute(OpenIdValidationFilter.USER_ATTRIBUTE, user);

    // continue chaining
    verify(chain).doFilter(request, response);
  }
}
