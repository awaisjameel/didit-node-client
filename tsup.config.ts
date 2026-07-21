import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  target: "es2022",
  platform: "node",
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  shims: false,
  skipNodeModulesBundle: true,
  treeshake: true,
  outDir: "dist",
});
