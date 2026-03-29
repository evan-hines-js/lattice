/**
 * Shared theme-aware styles for Lattice plugin components.
 *
 * Single source of truth for table styles, colors, and layout constants.
 * Every component uses this hook instead of extracting theme values locally.
 */

import { useTheme } from '@mui/material/styles';
import { useMemo } from 'react';

export function useLatticeStyles() {
  const theme = useTheme();

  return useMemo(() => {
    const textPrimary = theme.palette.text.primary;
    const textSecondary = theme.palette.text.secondary;
    const borderColor = theme.palette.divider;

    return {
      theme,
      textPrimary,
      textSecondary,
      borderColor,
      bgPaper: theme.palette.background.paper,
      bgDefault: theme.palette.background.default,
      errorColor: theme.palette.error.main,
      successColor: theme.palette.success.main,
      warningColor: theme.palette.warning.main,
      infoColor: theme.palette.info.main,

      th: {
        padding: '8px 12px',
        color: textSecondary,
        fontWeight: 600,
        fontSize: 13,
        textAlign: 'left' as const,
      },
      td: {
        padding: '8px 12px',
        color: textPrimary,
        fontSize: 13,
      },
      headerRow: {
        borderBottom: `2px solid ${borderColor}`,
        textAlign: 'left' as const,
      },
      bodyRow: {
        borderBottom: `1px solid ${borderColor}`,
      },
      table: {
        width: '100%' as const,
        borderCollapse: 'collapse' as const,
      },
      input: {
        padding: '6px 12px',
        border: `1px solid ${borderColor}`,
        borderRadius: 4,
        background: theme.palette.background.paper,
        color: textPrimary,
      },
    };
  }, [theme]);
}
