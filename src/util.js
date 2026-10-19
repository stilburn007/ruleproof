import path from "node:path";

export const SEVERITY = Object.freeze({
  info: 1,
  warning: 2,
  error: 3,
});

export function approxTokens(text) {
  return Math.max(1, Math.ceil(String(text).length / 4));
}

export function normalizeText(text) {
  return String(text)
    .toLowerCase()
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`([^`]+)`/g, " $1 ")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, " $1 ")
    .replace(/[^a-z0-9+#./:_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function wordSet(text) {
  return new Set(
    normalizeText(text)
      .split(" ")
      .map((word) => word.replace(/^[-.]+|[-.]+$/g, ""))
      .filter((word) => word.length > 2),
  );
}

export function jaccard(left, right) {
  const a = left instanceof Set ? left : wordSet(left);
  const b = right instanceof Set ? right : wordSet(right);
  if (a.size === 0 || b.size === 0) {
    return 0;
  }

  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) {
      intersection += 1;
    }
  }
  return intersection / (a.size + b.size - intersection);
}

export function redactSecret(value) {
  const text = String(value);
  if (text.length <= 8) {
    return `${text.slice(0, 2)}...`;
  }
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
}

export function severityRank(value) {
  return SEVERITY[value] ?? 0;
}

export function compareSeverity(left, right) {
  return severityRank(right) - severityRank(left);
}

export function toPosixPath(value) {
  return String(value).replace(/\\/g, "/");
}

export function relativePath(root, absolutePath) {
  const result = path.relative(root, absolutePath);
  return toPosixPath(result || ".");
}

export function globToRegExp(glob) {
  const normalized = toPosixPath(glob).replace(/^\.\//, "");
  let source = "^";

  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index];
    const next = normalized[index + 1];

    if (char === "*" && next === "*") {
      if (normalized[index + 2] === "/") {
        source += "(?:.*/)?";
        index += 2;
      } else {
        source += ".*";
        index += 1;
      }
      continue;
    }

    if (char === "*") {
      source += "[^/]*";
      continue;
    }

    if (char === "?") {
      source += "[^/]";
      continue;
    }

    source += char.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
  }

  source += "$";
  return new RegExp(source);
}

export function matchesAnyGlob(filePath, patterns = []) {
  const normalized = toPosixPath(filePath).replace(/^\.\//, "");
  return patterns.some((pattern) => globToRegExp(pattern).test(normalized));
}

export function uniqueBy(items, keyFn) {
  const seen = new Set();
  return items.filter((item) => {
    const key = keyFn(item);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(value);
}

export function stableDirectiveId(file, line, text) {
  const seed = `${file}:${line}:${normalizeText(text)}`;
  let hash = 2166136261;
  for (let index = 0; index < seed.length; index += 1) {
    hash ^= seed.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}
