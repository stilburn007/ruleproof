import fs from "node:fs/promises";
import path from "node:path";

const CONFIG_NAME = ".ruleproof.json";

export const DEFAULT_CONFIG = Object.freeze({
  ignore: [],
  files: [],
  budget: {
    warning: 2500,
    error: 5000,
  },
  failOn: "error",
  minScore: 0,
  rules: {},
  allow: [],
});

function mergeConfig(base, override) {
  return {
    ...base,
    ...override,
    budget: {
      ...base.budget,
      ...(override.budget ?? {}),
    },
    ignore: override.ignore ?? base.ignore,
    files: override.files ?? base.files,
    rules: {
      ...base.rules,
      ...(override.rules ?? {}),
    },
    allow: override.allow ?? base.allow,
  };
}

export async function loadConfig(root, explicitPath) {
  const target = explicitPath
    ? path.resolve(root, explicitPath)
    : path.join(root, CONFIG_NAME);

  try {
    const source = await fs.readFile(target, "utf8");
    let parsed;
    try {
      parsed = JSON.parse(source);
    } catch (error) {
      throw new Error(`Invalid JSON in ${path.relative(root, target)}: ${error.message}`);
    }
    return {
      config: mergeConfig(DEFAULT_CONFIG, parsed),
      path: target,
    };
  } catch (error) {
    if (error.code === "ENOENT" && !explicitPath) {
      return { config: { ...DEFAULT_CONFIG }, path: null };
    }
    throw error;
  }
}

export function configTemplate() {
  return `${JSON.stringify(
    {
      ignore: ["vendor/**", "examples/**"],
      files: [],
      budget: {
        warning: 2500,
        error: 5000,
      },
      failOn: "error",
      minScore: 0,
      rules: {
        "duplicate-instruction": "info",
        "absolute-path": "warning",
      },
      allow: [],
    },
    null,
    2,
  )}\n`;
}
