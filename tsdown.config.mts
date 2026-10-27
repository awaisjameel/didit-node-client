import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  target: "es2022",
  platform: "node",
  dts: true,
  tsconfig: "tsconfig.build.json",
  sourcemap: true,
  clean: true,
  outDir: "dist",
  outExtensions: ({ format }) => ({
    js: format === "cjs" ? ".js" : ".mjs",
    dts: format === "cjs" ? ".d.ts" : ".d.mts",
  }),
});
