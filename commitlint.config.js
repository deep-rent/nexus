/** @type {import('@commitlint/types/lib').UserConfig} */
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "scope-enum": [2, "always", []],
  },
};
