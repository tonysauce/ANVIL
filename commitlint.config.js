module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat', // New feature
        'fix', // Bug fix
        'docs', // Documentation
        'style', // Code style changes
        'refactor', // Code refactoring
        'perf', // Performance improvements
        'test', // Tests
        'build', // Build system changes
        'ci', // CI/CD changes
        'chore', // Maintenance
        'revert', // Revert previous commit
        'security', // Security improvements
        'config', // Configuration changes
        'deploy', // Deployment related
      ],
    ],
    'subject-case': [0],
    'subject-max-length': [2, 'always', 100],
    'body-max-line-length': [2, 'always', 200],
  },
};
