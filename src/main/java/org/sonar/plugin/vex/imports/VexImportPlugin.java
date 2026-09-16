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
        .description("When disabled, opening the VEX Import tab on any project shows a disabled notice instead of the wizard, and no API calls are made. Takes effect immediately - no SonarQube restart needed. The tab itself stays visible in the menu either way (SonarQube's page registry can't be changed after startup), only its content changes.")
        .defaultValue("true")
        .type(PropertyType.BOOLEAN)
        .category(CATEGORY)
        .build()
    );
  }
}
