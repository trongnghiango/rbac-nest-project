// @ts-check
import eslint from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['eslint.config.mjs'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  eslintPluginPrettierRecommended,
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
      sourceType: 'commonjs',
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-floating-promises': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      "prettier/prettier": ["error", { endOfLine: "auto" }],
      // --- THÊM ĐOẠN NÀY ĐỂ FIX VỤ DẤU GẠCH DƯỚI (_) ---
      '@typescript-eslint/no-unused-vars': [
        'error', // Hoặc 'error' nếu muốn chặt chẽ
        {
          argsIgnorePattern: '^_',         // Bỏ qua tham số hàm bắt đầu bằng _
          varsIgnorePattern: '^_',         // Bỏ qua biến bắt đầu bằng _
          caughtErrorsIgnorePattern: '^_', // Bỏ qua lỗi trong catch bắt đầu bằng _
        },
      ],
    },
  },
);
