import { approxTokens, stableDirectiveId } from "./util.js";

const NEGATIVE_PATTERN =
  /\b(never|do not|don't|avoid|must not|should not|cannot|can't|not allowed|forbidden|prohibit(?:ed)?)\b/i;
const POSITIVE_PATTERN =
  /\b(always|must|required|require|use|run|prefer|should|ensure|only|need to|make sure)\b/i;
const DIRECTIVE_HINT =
  /\b(always|must|required|require|use|run|prefer|should|never|avoid|ensure|only|install|test|lint|format|commit|branch|edit|modify|write|read|do not|don't|cannot|can't)\b/i;

const PACKAGE_MANAGERS = ["pnpm", "npm", "yarn", "bun"];
const COMMAND_STARTS = [
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "npx",
  "node",
  "python",
  "python3",
  "pytest",
  "tox",
  "nox",
  "uv",
  "poetry",
  "pip",
  "git",
  "gh",
  "make",
  "just",
  "cargo",
  "rustfmt",
  "go",
  "dotnet",
  "mvn",
  "gradle",
  "docker",
  "kubectl",
  "terraform",
  "az",
  "aws",
  "dbt",
  "ruff",
  "biome",
  "eslint",
  "prettier",
  "tsc",
  "jest",
  "vitest",
  "playwright",
  "deno",
  "php",
  "composer",
  "ruby",
  "bundle",
  "rake",
  "swift",
  "xcodebuild",
];

function extractCodeSpans(text) {
  const spans = [];
  const pattern = /`([^`\n]+)`/g;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    spans.push(match[1].trim());
  }
  return spans;
}

function stripPromptPrefix(command) {
  return command.replace(/^\s*(?:\$|>|PS>|❯)\s*/, "").trim();
}

export function isCommandLike(value) {
  const command = stripPromptPrefix(value);
  if (!command || command.length > 240 || /^https?:\/\//i.test(command)) {
    return false;
  }
  if (/^(?:\.{0,2}\/|scripts\/|tools\/)/.test(command)) {
    return true;
  }
  const first = command.split(/\s+/)[0].toLowerCase();
  return COMMAND_STARTS.includes(first) || /^[\w.-]+\.(?:sh|ps1|cmd|bat)$/i.test(first);
}

function canonicalCommand(command) {
  return stripPromptPrefix(command)
    .replace(/\s+/g, " ")
    .replace(/\s*(?:#.*)$/, "")
    .trim();
}

function extractCommands(text) {
  const commands = extractCodeSpans(text)
    .map(stripPromptPrefix)
    .filter(isCommandLike);

  const candidate = stripPromptPrefix(text.replace(/^[-*+]\s+/, "").replace(/^\d+\.\s+/, ""));
  if (commands.length === 0 && isCommandLike(candidate) && !candidate.includes("`")) {
    commands.push(candidate);
  }

  return [...new Set(commands.map(canonicalCommand))];
}

function extractPackageManagers(text, commands) {
  const managers = new Set();
  for (const command of commands) {
    const first = command.split(/\s+/)[0]?.toLowerCase();
    if (PACKAGE_MANAGERS.includes(first)) {
      managers.add(first);
    }
  }

  const pattern = /\b(pnpm|npm|yarn|bun)\b(?:\s+(?:install|add|remove|run|test|exec|dlx|create|init|ci|why|workspace))?/gi;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    if (match[1]) {
      managers.add(match[1].toLowerCase());
    }
  }
  return [...managers];
}

function extractFormatting(text) {
  const values = new Set();
  const lower = text.toLowerCase();

  if (/\b(?:hard )?tabs?\b/.test(lower)) values.add("tabs");
  if (/\b(?:soft )?spaces?\b/.test(lower)) values.add("spaces");
  if (/\b(?:2|two)[ -]space/.test(lower)) values.add("2-space");
  if (/\b(?:4|four)[ -]space/.test(lower)) values.add("4-space");
  if (/\bprettier\b/.test(lower)) values.add("prettier");
  if (/\bbiome\b/.test(lower)) values.add("biome");
  if (/\bblack\b/.test(lower)) values.add("black");
  if (/\bruff(?: format)?\b/.test(lower)) values.add("ruff");
  if (/\bgofmt\b/.test(lower)) values.add("gofmt");
  if (/\brustfmt\b/.test(lower)) values.add("rustfmt");
  if (/\beslint\b/.test(lower)) values.add("eslint");
  if (/\b(?:single|double)[ -]quotes?\b/.test(lower)) {
    values.add(/single/.test(lower) ? "single-quotes" : "double-quotes");
  }
  if (/\bsemicolons?\b/.test(lower)) {
    values.add(/no semicolons?|without semicolons?/.test(lower) ? "no-semicolons" : "semicolons");
  }

  return [...values];
}

function looksLikePath(value) {
  const candidate = value.trim().replace(/^['"]|['"]$/g, "");
  if (!candidate || candidate.length > 180 || candidate.includes(" ")) return false;
  if (/^(?:https?:|mailto:|data:|npm:|node:|git\+)/i.test(candidate)) return false;
  if (/^[a-z]+:\/\//i.test(candidate)) return false;
  if (/^[\d.^~<>]+$/.test(candidate)) return false;
  if (candidate.includes("<") || candidate.includes(">") || candidate.includes("$")) return false;
  if (candidate.startsWith("#")) return false;
  if (isCommandLike(candidate)) return false;
  if (candidate.startsWith("./") || candidate.startsWith("../") || candidate.startsWith("/")) {
    return true;
  }
  if (candidate.includes("/") || candidate.includes("\\")) {
    return /[a-z0-9_*@.~-]+(?:\/|\\)/i.test(candidate);
  }
  return /\.(?:md|mdx|txt|json|jsonc|toml|ya?ml|js|mjs|cjs|ts|tsx|jsx|py|rs|go|java|kt|swift|rb|php|css|scss|html|sql|sh|ps1|cmd|bat|lock)$/i.test(
    candidate,
  );
}

function normalizePathReference(value) {
  return value
    .trim()
    .replace(/^['"]|['"]$/g, "")
    .replace(/[),.;:]+$/g, "")
    .replace(/^<(.*)>$/, "$1")
    .replace(/^\.\//, "");
}

function extractPathRefs(text) {
  const refs = new Set();

  const markdownLinks = /\[[^\]]*\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)/g;
  let match;
  while ((match = markdownLinks.exec(text)) !== null) {
    if (looksLikePath(match[1])) {
      refs.add(normalizePathReference(match[1]));
    }
  }

  for (const span of extractCodeSpans(text)) {
    if (looksLikePath(span)) {
      refs.add(normalizePathReference(span));
    }
  }

  const atRefs = /(?:^|\s)@([\w./-]+\.[a-z0-9]+)/gi;
  while ((match = atRefs.exec(text)) !== null) {
    refs.add(normalizePathReference(match[1]));
  }

  return [...refs];
}

function cleanDirectiveText(text) {
  return text
    .replace(/^\s{0,3}#{1,6}\s+/, "")
    .replace(/^\s*[-*+]\s+/, "")
    .replace(/^\s*\d+\.\s+/, "")
    .replace(/^\s*\[[ xX]\]\s+/, "")
    .replace(/\s+/g, " ")
    .trim();
}

function directivePolarity(text) {
  if (NEGATIVE_PATTERN.test(text)) return "negative";
  if (POSITIVE_PATTERN.test(text)) return "positive";
  return "neutral";
}

function looksLikeDirective(line, cleaned) {
  if (cleaned.length < 4) return false;
  if (line.trim().startsWith("<!--")) return false;
  if (/^\s*---\s*$/.test(line)) return false;
  if (/^\s*#/.test(line) && !DIRECTIVE_HINT.test(cleaned)) return false;
  if (/^\s*[-*+]\s+/.test(line)) return true;
  if (/^\s*\d+\.\s+/.test(line)) return true;
  if (extractCodeSpans(line).some(isCommandLike)) return true;
  return DIRECTIVE_HINT.test(cleaned);
}

function createDirective(file, line, section, text) {
  const cleaned = cleanDirectiveText(text);
  const commands = extractCommands(text);
  const packageManagers = extractPackageManagers(text, commands);
  const formatting = extractFormatting(text);
  const pathRefs = extractPathRefs(text);
  const polarity = directivePolarity(text);
  const commitPolicy = /\bcommit(?:s|ted|ting)?\b/i.test(text)
    ? polarity === "negative"
      ? "forbid"
      : "require"
    : null;

  return {
    id: stableDirectiveId(file.path, line, cleaned),
    file: file.path,
    fileKind: file.kind,
    line,
    section,
    text: cleaned,
    raw: text.trim(),
    polarity,
    commands,
    packageManagers,
    formatting,
    pathRefs,
    commitPolicy,
  };
}

export function parseInstructionFile(file) {
  const lines = file.content.split(/\r?\n/);
  const directives = [];
  const headings = [];
  let inFence = false;
  let fenceLanguage = "";

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const trimmed = line.trim();

    if (/^```/.test(trimmed)) {
      if (inFence) {
        inFence = false;
        fenceLanguage = "";
      } else {
        inFence = true;
        fenceLanguage = trimmed.slice(3).trim();
      }
      return;
    }

    if (inFence) {
      const command = stripPromptPrefix(trimmed);
      if (
        command &&
        !command.startsWith("#") &&
        !command.startsWith("//") &&
        fenceLanguage !== "json" &&
        fenceLanguage !== "yaml" &&
        fenceLanguage !== "yml" &&
        isCommandLike(command)
      ) {
        directives.push(createDirective(file, lineNumber, headings.at(-1) ?? "", command));
      }
      return;
    }

    const heading = line.match(/^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$/);
    if (heading) {
      const level = heading[1].length;
      headings[level - 1] = heading[2].trim();
      headings.length = level;
      return;
    }

    const cleaned = cleanDirectiveText(line);
    if (!looksLikeDirective(line, cleaned)) {
      return;
    }

    directives.push(createDirective(file, lineNumber, headings.filter(Boolean).join(" > "), line));
  });

  return {
    path: file.path,
    kind: file.kind,
    content: file.content,
    bytes: file.bytes,
    tokens: approxTokens(file.content),
    directives,
  };
}

export function parseInstructions(files) {
  return files.map(parseInstructionFile);
}
