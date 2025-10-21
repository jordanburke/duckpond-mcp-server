import type { Options } from "tsup"

const env = process.env.NODE_ENV

export const tsup: Options = {
  splitting: true,
  sourcemap: true,
  clean: true, // rimraf disr
  dts: true, // generate dts file for main module
  format: ["esm"], // ESM only - functype requires ESM
  minify: env === "production",
  bundle: env === "production",
  skipNodeModulesBundle: true,
  watch: env === "development",
  target: "es2020",
  outDir: env === "production" ? "dist" : "lib",
  entry: ["src/index.ts", "src/**/*.ts"],
}
