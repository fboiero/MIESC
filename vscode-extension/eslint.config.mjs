import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
    eslint.configs.recommended,
    ...tseslint.configs.recommended,
    {
        rules: {
            "@typescript-eslint/naming-convention": [
                "warn",
                {
                    selector: "import",
                    format: ["camelCase", "PascalCase"],
                },
            ],
            "@typescript-eslint/no-unused-vars": "warn",
            "@typescript-eslint/no-explicit-any": "warn",
            curly: "warn",
            eqeqeq: "warn",
            "no-throw-literal": "warn",
            semi: "off",
        },
    },
    {
        ignores: ["out/", "dist/", "**/*.d.ts"],
    }
);
