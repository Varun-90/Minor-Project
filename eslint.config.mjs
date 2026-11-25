import firebaseRulesPlugin from '@firebase/eslint-plugin-security-rules';

export default [
  {
    ignores: [
      'dist/**/*',
      'node_modules/**/*',
      'frontend/**/*',
      'backend/**/*',
      'ml/**/*',
      'database/**/*',
      'docs/**/*',
      'server.ts',
    ],
  },
  firebaseRulesPlugin.configs['flat/recommended'],
];
