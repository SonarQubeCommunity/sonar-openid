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

import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;
import org.sonar.api.web.ServletFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public final class OpenIdLogoutFilter extends ServletFilter {

  static final String PROPERTY_PROVIDER_LOGOUT_URL = "sonar.openid.providerLogoutUrl";
  static final Logger LOG = LoggerFactory.getLogger(OpenIdLogoutFilter.class);

  private final Settings settings;

  public OpenIdLogoutFilter(Settings settings) {
    this.settings = settings;
  }

  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create("/sessions/logout");
  }

  public void init(FilterConfig filterConfig) throws ServletException {
    String providerLogoutUrl = getLogoutUrl();
    if (Strings.isNullOrEmpty(providerLogoutUrl)) {
      LOG.info("No OpenID logout URL");
    } else {
      LOG.info("OpenID logout URL: " + providerLogoutUrl);
    }
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
    String providerLogoutUrl = getLogoutUrl();
    if (!Strings.isNullOrEmpty(providerLogoutUrl)) {
      HttpSession session = ((HttpServletRequest) request).getSession(false);
      if (session != null) {
        session.invalidate();
      }
      ((HttpServletResponse) response).sendRedirect(providerLogoutUrl);
    } else {
      filterChain.doFilter(request, response);
    }
  }

  private String getLogoutUrl() {
    return settings.getString(PROPERTY_PROVIDER_LOGOUT_URL);
  }

  public void destroy() {
  }
}