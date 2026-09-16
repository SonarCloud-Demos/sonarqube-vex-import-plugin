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

import org.sonar.api.web.page.Context;
import org.sonar.api.web.page.Page;
import org.sonar.api.web.page.Page.Qualifier;
import org.sonar.api.web.page.Page.Scope;
import org.sonar.api.web.page.PageDefinition;

/** Project tab. Always registered - the page registry is built once at
 * startup with no supported way to add/remove a page afterward, so the
 * veximport.enabled setting is enforced at runtime instead (see
 * api/pluginSettings.ts), not by conditionally skipping registration here.
 * That keeps toggling the setting instantaneous: no SonarQube restart. */
public class VexImportPageDefinition implements PageDefinition {

  @Override
  public void define(Context context) {
    context.addPage(Page.builder("veximport/vex_import")
      .setName("VEX Import")
      .setScope(Scope.COMPONENT)
      .setComponentQualifiers(Qualifier.PROJECT)
      .build());
  }
}
