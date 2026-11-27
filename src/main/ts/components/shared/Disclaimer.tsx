import React from 'react';

export function Disclaimer() {
  return (
    <div
      style={{
        fontSize: '12px',
        color: '#92400e',
        background: '#fffbeb',
        border: '1px solid #fde68a',
        borderRadius: '4px',
        marginBottom: '12px',
        padding: '6px 10px',
      }}
      data-testid="disclaimer"
    >
      <strong>Provided as is.</strong> This plugin is not part of Sonar's officially supported products, and Sonar
      Support does not cover it.
    </div>
  );
}
