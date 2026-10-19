import fs from "node:fs/promises";
import path from "node:path";
import { matchesAnyGlob, relativePath, toPosixPath } from "./util.js";

const DEFAULT_IGNORES = [
  ".git/**",
  "node_modules/**",
  "dist/**",
  "build/**",
  "coverage/**",
  ".next/**",
  ".nuxt/**",
  "vendor/**",
  "target/**",
  "out/**",
  ".venv/**",
  "venv/**",
  "__pycache__/**",
  "*.min.js",
];

const EXACT_INSTRUCTION_FILES = new Set([
  "AGENTS.md",
  "AGENTS.override.md",
  "CLAUDE.md",
  "GEMINI.md",
  ".cursorrules",
  ".windsurfrules",
  ".clinerules",
  "copilot-instructions.md",
]);

const MAX_FILES = 200;
const MAX_FILE_BYTES = 1024 * 1024;
const MCP_CONFIG_NAMES = new Set([".mcp.json", "mcp.json"]);

export function instructionKind(filePath) {
  const normalized = toPosixPath(filePath);
  const base = path.posix.basename(normalized);

  if (base === "AGENTS.md" || base === "AGENTS.override.md") return "AGENTS.md";
  if (base === "CLAUDE.md") return "Claude";
  if (base === "GEMINI.md") return "Gemini";
  if (base === ".cursorrules" || normalized.includes(".cursor/rules/")) return "Cursor";
  if (base === ".windsurfrules") return "Windsurf";
  if (base === ".clinerules") return "Cline";
  if (base === "copilot-instructions.md" || normalized.includes(".github/instructions/")) {
    return "Copilot";
  }
  return "Agent instructions";
}

function isInstructionPath(filePath) {
  const normalized = toPosixPath(filePath);
  const base = path.posix.basename(normalized);

  if (EXACT_INSTRUCTION_FILES.has(base)) {
    return true;
  }

  if (normalized.includes(".cursor/rules/") && /\.(md|mdc)$/i.test(base)) {
    return true;
  }

  if (normalized.includes(".github/instructions/") && base.endsWith(".instructions.md")) {
    return true;
  }

  return false;
}

export async function discoverInstructionFiles(root, config = {}) {
  const ignore = [...DEFAULT_IGNORES, ...(config.ignore ?? [])];
  const extraPatterns = config.files ?? [];
  const results = [];
  let visited = 0;

  async function walk(directory) {
    if (results.length >= MAX_FILES || visited > 50000) {
      return;
    }

    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }

    entries.sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of entries) {
      if (results.length >= MAX_FILES) {
        return;
      }

      const absolute = path.join(directory, entry.name);
      const rel = relativePath(root, absolute);

      if (matchesAnyGlob(rel, ignore) || matchesAnyGlob(`${rel}/`, ignore)) {
        continue;
      }

      if (entry.isDirectory()) {
        if (entry.name === ".git" || entry.name === "node_modules") {
          continue;
        }
        await walk(absolute);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      visited += 1;
      if (isInstructionPath(rel) || matchesAnyGlob(rel, extraPatterns)) {
        results.push(absolute);
      }
    }
  }

  await walk(root);

  const files = [];
  for (const absolute of results) {
    try {
      const stat = await fs.stat(absolute);
      if (stat.size > MAX_FILE_BYTES) {
        continue;
      }
      const content = await fs.readFile(absolute, "utf8");
      files.push({
        path: relativePath(root, absolute),
        absolutePath: absolute,
        kind: instructionKind(relativePath(root, absolute)),
        content,
        bytes: stat.size,
      });
    } catch {
      // A file can disappear during a scan in an active worktree.
    }
  }

  return files.sort((left, right) => left.path.localeCompare(right.path));
}

export async function discoverMcpConfigs(root, config = {}) {
  const ignore = [...DEFAULT_IGNORES, ...(config.ignore ?? [])];
  const results = [];

  async function walk(directory) {
    if (results.length >= 50) return;
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }

    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (results.length >= 50) return;
      const absolute = path.join(directory, entry.name);
      const rel = relativePath(root, absolute);
      if (matchesAnyGlob(rel, ignore) || matchesAnyGlob(`${rel}/`, ignore)) {
        continue;
      }
      if (entry.isDirectory()) {
        if (entry.name === ".git" || entry.name === "node_modules") continue;
        await walk(absolute);
      } else if (entry.isFile() && MCP_CONFIG_NAMES.has(entry.name)) {
        results.push(absolute);
      }
    }
  }

  await walk(root);

  const files = [];
  for (const absolute of results) {
    try {
      const stat = await fs.stat(absolute);
      if (stat.size > MAX_FILE_BYTES) continue;
      const content = await fs.readFile(absolute, "utf8");
      files.push({
        path: relativePath(root, absolute),
        content,
        bytes: stat.size,
      });
    } catch {
      // Ignore files removed while scanning.
    }
  }
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

export async function readJsonIfExists(filePath) {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8"));
  } catch {
    return null;
  }
}

export async function readTextIfExists(filePath) {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

export async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function expandSimpleGlob(root, pattern) {
  const normalized = toPosixPath(pattern).replace(/^\.\//, "");
  if (!/[*?]/.test(normalized)) {
    return (await pathExists(path.join(root, normalized))) ? [normalized] : [];
  }

  const firstWildcard = normalized.search(/[*?]/);
  const staticPrefix = normalized.slice(0, firstWildcard);
  const slash = staticPrefix.lastIndexOf("/");
  const start = slash === -1 ? root : path.join(root, staticPrefix.slice(0, slash));
  const matcher = matchesAnyGlob;
  const matches = [];

  async function walk(directory) {
    if (matches.length >= 20) {
      return;
    }
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (matches.length >= 20) return;
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      const absolute = path.join(directory, entry.name);
      const rel = relativePath(root, absolute);
      if (entry.isDirectory()) {
        await walk(absolute);
      } else if (matcher(rel, [normalized])) {
        matches.push(rel);
      }
    }
  }

  await walk(start);
  return matches;
}
