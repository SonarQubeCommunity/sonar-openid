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
package org.sonar.plugins.openid.api;

import com.google.common.base.Throwables;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;

public final class OpenIdUtils {
  private OpenIdUtils() {
    // only static methods
  }

  public static <T> T getMessageAs(Class<T> c, AuthSuccess response, String typeUri) {
    try {
      T result = null;
      if (response.hasExtension(typeUri)) {
        MessageExtension me = response.getExtension(typeUri);
        result = c.cast(me);
      }
      return result;
    } catch (MessageException e) {
      throw Throwables.propagate(e);
    }
  }
}
