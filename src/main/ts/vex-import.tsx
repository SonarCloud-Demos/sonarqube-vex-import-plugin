import React from 'react';
import { VexImportWizard } from './components/VexImportWizard';

(globalThis as any).registerExtension('veximport/vex_import', (options: any) => {
  return <VexImportWizard component={options.component} branchLike={options.branchLike} />;
});
