/*
 * SonarQube VEX Import Plugin
 * Copyright (C) 2026 SonarSource Sàrl
 * mailto:info AT sonarsource DOT com
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.plugin.vex.imports;

import org.sonar.api.Plugin;
import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;

public class VexImportPlugin implements Plugin {

  public static final String ENABLED_KEY = "veximport.enabled";
  private static final String CATEGORY = "VEX Import";

  @Override
  public void define(Context context) {
    context.addExtension(VexImportPageDefinition.class);
    context.addExtension(
      PropertyDefinition.builder(ENABLED_KEY)
        .name("Enable VEX Import")
        .description("When disabled, the VEX Import project tab is not registered at all - no menu entry on any project, and no API calls. The page registry is built once, so toggling this requires a SonarQube restart before the tab appears or disappears; the disabled notice inside the page itself, though, takes effect immediately.")
        .defaultValue("true")
        .type(PropertyType.BOOLEAN)
        .category(CATEGORY)
        .build()
    );
  }
}
