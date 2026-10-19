import path from "node:path";
import {
  expandSimpleGlob,
  pathExists,
  readJsonIfExists,
  readTextIfExists,
} from "./files.js";
import { ruleSeverity } from "./rules.js";
import {
  jaccard,
  normalizeText,
  redactSecret,
  toPosixPath,
  uniqueBy,
  wordSet,
} from "./util.js";

const SECRET_PATTERNS = [
  {
    name: "AWS access key",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  },
  {
    name: "GitHub token",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g,
  },
  {
    name: "OpenAI key",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b/g,
  },
  {
    name: "Slack token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    name: "Google API key",
    pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  },
  {
    name: "JWT",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
];

const PROMPT_INJECTION_PATTERNS = [
  {
    name: "instruction override",
    pattern:
      /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system|developer)\s+(?:instructions?|rules?|prompts?)\b/i,
  },
  {
    name: "hidden behavior",
    pattern:
      /\b(?:do not|don't|never)\s+(?:tell|inform|notify|warn)\s+(?:the\s+)?(?:user|developer|operator)\b/i,
  },
  {
    name: "concealed action",
    pattern: /\b(?:hide|conceal)\s+(?:this|the)\s+(?:action|change|command|error)\b/i,
  },
  {
    name: "approval bypass",
    pattern: /\b(?:bypass|disable|skip)\s+(?:the\s+)?(?:approval|permission|safety|guardrail)s?\b/i,
  },
  {
    name: "data exfiltration",
    pattern:
      /\b(?:upload|send|post|transmit|exfiltrate)\b.{0,80}\b(?:\.env|secret|credential|token|private key|ssh key)\b/i,
  },
];

const DANGEROUS_COMMAND_PATTERNS = [
  {
    name: "root deletion",
    pattern: /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:\/|~|\$HOME)(?:\s|$)/i,
  },
  {
    name: "recursive force deletion",
    pattern: /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+\*/i,
  },
  {
    name: "remote script execution",
    pattern: /\b(?:curl|wget)\b[^|;\n]*\|\s*(?:ba|z|da|fi)?sh\b/i,
  },
  {
    name: "world-writable permissions",
    pattern: /\bchmod\s+(?:-R\s+)?777\b/i,
  },
  {
    name: "unreviewed privilege escalation",
    pattern: /\bsudo\s+\S+/i,
  },
  {
    name: "forced history rewrite",
    pattern: /\bgit\s+push\b[^\n]*\s(?:--force|-f)\b/i,
  },
  {
    name: "destructive reset",
    pattern: /\bgit\s+reset\s+--hard\b/i,
  },
  {
    name: "permission bypass flag",
    pattern: /--dangerously-skip-permissions\b|\s--yolo\b/i,
  },
];

const FORMATTER_GROUPS = [
  ["prettier", "biome"],
  ["black", "ruff"],
];

function finding(rule, severity, message, files, options = {}) {
  return {
    rule,
    severity,
    message,
    files: uniqueBy(
      files.filter(Boolean).map((file) => ({
        path: file.path,
        line: file.line ?? null,
      })),
      (file) => `${file.path}:${file.line ?? ""}`,
    ),
    evidence: options.evidence ?? null,
    suggestion: options.suggestion ?? null,
    details: options.details ?? null,
  };
}

function lineId(file, line) {
  return { path: file.path, line };
}

function scanSecrets(instructions, config) {
  const findings = [];
  for (const file of instructions) {
    file.content.split(/\r?\n/).forEach((line, index) => {
      for (const secret of SECRET_PATTERNS) {
        secret.pattern.lastIndex = 0;
        let match;
        while ((match = secret.pattern.exec(line)) !== null) {
          const value = match[0];
          if (/(?:example|placeholder|your_|xxxx|redacted|\.\.\.)/i.test(value)) {
            continue;
          }
          const severity = ruleSeverity("secret-detected", config);
          if (severity) {
            findings.push(
              finding(
                "secret-detected",
                severity,
                `${secret.name} is embedded in an agent instruction file.`,
                [lineId(file, index + 1)],
                {
                  evidence: redactSecret(value),
                  suggestion: "Remove the value, rotate it, and reference an environment variable instead.",
                },
              ),
            );
          }
        }
      }

      if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(line)) {
        const severity = ruleSeverity("private-key-detected", config);
        if (severity) {
          findings.push(
            finding(
              "private-key-detected",
              severity,
              "A private key block appears in an agent instruction file.",
              [lineId(file, index + 1)],
              {
                evidence: "-----BEGIN PRIVATE KEY-----",
                suggestion: "Remove the key from the repository and rotate it immediately.",
              },
            ),
          );
        }
      }
    });
  }
  return findings;
}

function scanTextHazards(instructions, config) {
  const findings = [];
  for (const file of instructions) {
    file.content.split(/\r?\n/).forEach((line, index) => {
      for (const injection of PROMPT_INJECTION_PATTERNS) {
        if (!injection.pattern.test(line)) continue;
        const severity = ruleSeverity("prompt-injection", config);
        if (severity) {
          findings.push(
            finding(
              "prompt-injection",
              severity,
              `Possible prompt injection: ${injection.name}.`,
              [lineId(file, index + 1)],
              {
                evidence: line.trim().slice(0, 180),
                suggestion:
                  "Treat instruction files as trusted source code. Remove instructions that hide actions or override safety rules.",
              },
            ),
          );
        }
      }

      for (const dangerous of DANGEROUS_COMMAND_PATTERNS) {
        if (!dangerous.pattern.test(line)) continue;
        const severity = ruleSeverity("dangerous-command", config);
        if (severity) {
          findings.push(
            finding(
              "dangerous-command",
              severity,
              `Unsafe command pattern: ${dangerous.name}.`,
              [lineId(file, index + 1)],
              {
                evidence: line.trim().slice(0, 180),
                suggestion: "Replace it with a bounded, reviewable command and require human approval.",
              },
            ),
          );
        }
      }

      if (/\b(?:[A-Za-z]:\\Users\\|\/Users\/|\/home\/)[^\s`'"]+/i.test(line)) {
        const severity = ruleSeverity("absolute-path", config);
        if (severity) {
          findings.push(
            finding(
              "absolute-path",
              severity,
              "Instruction contains a machine-specific absolute path.",
              [lineId(file, index + 1)],
              {
                evidence: line.trim().slice(0, 180),
                suggestion: "Use a repository-relative path so every contributor and agent sees the same files.",
              },
            ),
          );
        }
      }
    });
  }
  return findings;
}

function mcpServers(config) {
  const containers = [config?.mcpServers, config?.servers, config?.context_servers];
  const servers = [];
  for (const container of containers) {
    if (!container || typeof container !== "object" || Array.isArray(container)) continue;
    for (const [name, value] of Object.entries(container)) {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        servers.push({ name, value });
      }
    }
  }
  return servers;
}

function packageSpecIsPinned(value) {
  const spec = String(value);
  if (!spec || spec.startsWith("-")) return true;
  if (spec.startsWith("@")) {
    const separator = spec.indexOf("@", 1);
    if (separator === -1) return false;
    return !/@(?:latest|next|canary|beta|alpha)$/i.test(spec);
  }
  if (!spec.includes("@")) return false;
  return !/@(?:latest|next|canary|beta|alpha)$/i.test(spec);
}

function scanMcpConfigs(mcpFiles, config) {
  const findings = [];

  for (const file of mcpFiles) {
    let parsed;
    try {
      parsed = JSON.parse(file.content);
    } catch (error) {
      const severity = ruleSeverity("mcp-config-invalid", config);
      if (severity) {
        findings.push(
          finding(
            "mcp-config-invalid",
            severity,
            `MCP configuration is not valid JSON: ${error.message}`,
            [{ path: file.path, line: 1 }],
            {
              suggestion: "Fix the JSON syntax before any agent tries to load the server configuration.",
            },
          ),
        );
      }
      continue;
    }

    const servers = mcpServers(parsed);
    for (const { name, value } of servers) {
      const command = typeof value.command === "string" ? value.command : "";
      const argList = Array.isArray(value.args)
        ? value.args.map(String)
        : typeof value.args === "string"
          ? [value.args]
          : [];
      const commandLine = [command, ...argList].filter(Boolean).join(" ").trim();

      for (const dangerous of DANGEROUS_COMMAND_PATTERNS) {
        if (!dangerous.pattern.test(commandLine)) continue;
        const severity = ruleSeverity("dangerous-command", config);
        if (severity) {
          findings.push(
            finding(
              "dangerous-command",
              severity,
              `MCP server "${name}" starts with an unsafe command pattern: ${dangerous.name}.`,
              [{ path: file.path, line: 1 }],
              {
                evidence: commandLine.slice(0, 220),
                suggestion:
                  "Use a bounded server command, pin its package, and require approval for destructive operations.",
              },
            ),
          );
        }
      }

      if (["npx", "bunx", "pnpx", "uvx"].includes(path.basename(command))) {
        const packageArg = argList.find((arg) => !arg.startsWith("-"));
        if (!packageArg) {
          const severity = ruleSeverity("mcp-config-invalid", config);
          if (severity) {
            findings.push(
              finding(
                "mcp-config-invalid",
                severity,
                `MCP server "${name}" uses ${command} without a package name.`,
                [{ path: file.path, line: 1 }],
                {
                  evidence: commandLine,
                  suggestion: "Add an explicit, versioned package name.",
                },
              ),
            );
          }
        } else if (!packageSpecIsPinned(packageArg)) {
          const severity = ruleSeverity("mcp-unpinned-server", config);
          if (severity) {
            findings.push(
              finding(
                "mcp-unpinned-server",
                severity,
                `MCP server "${name}" launches an unpinned package.`,
                [{ path: file.path, line: 1 }],
                {
                  evidence: `${command} ${packageArg}`,
                  suggestion:
                    "Pin an exact version or commit SHA so an upstream release cannot silently change agent capabilities.",
                },
              ),
            );
          }
        }
      }

      if (/^http:\/\//i.test(value.url ?? "")) {
        const severity = ruleSeverity("mcp-insecure-transport", config);
        if (severity) {
          findings.push(
            finding(
              "mcp-insecure-transport",
              severity,
              `MCP server "${name}" uses plaintext HTTP.`,
              [{ path: file.path, line: 1 }],
              {
                evidence: String(value.url),
                suggestion: "Use HTTPS or a local stdio transport.",
              },
            ),
          );
        }
      }

      const pathsToCheck = [
        value.cwd,
        ...argList.filter((arg) =>
          /\b(?:[A-Za-z]:\\Users\\|\/Users\/|\/home\/|~\/)[^\s]+/i.test(arg),
        ),
      ].filter(Boolean);
      if (pathsToCheck.length > 0) {
        const severity = ruleSeverity("absolute-path", config);
        if (severity) {
          findings.push(
            finding(
              "absolute-path",
              severity,
              `MCP server "${name}" depends on a machine-specific path.`,
              [{ path: file.path, line: 1 }],
              {
                evidence: pathsToCheck.join("\n").slice(0, 220),
                suggestion: "Use a workspace-relative path or a documented environment variable.",
              },
            ),
          );
        }
      }

      if (value.env && typeof value.env === "object" && !Array.isArray(value.env)) {
        for (const [envName, envValue] of Object.entries(value.env)) {
          if (typeof envValue !== "string") continue;
          for (const secret of SECRET_PATTERNS) {
            secret.pattern.lastIndex = 0;
            const match = secret.pattern.exec(envValue);
            if (!match || /(?:example|placeholder|your_|xxxx|redacted)/i.test(match[0])) {
              continue;
            }
            const severity = ruleSeverity("secret-detected", config);
            if (severity) {
              findings.push(
                finding(
                  "secret-detected",
                  severity,
                  `MCP server "${name}" embeds a ${secret.name} in ${envName}.`,
                  [{ path: file.path, line: 1 }],
                  {
                    evidence: redactSecret(match[0]),
                    suggestion: "Reference an environment variable supplied by the host, then rotate the key.",
                  },
                ),
              );
            }
          }
        }
      }
    }
  }
  return findings;
}

async function repositoryPackageMetadata(root) {
  const packageJson = await readJsonIfExists(path.join(root, "package.json"));
  const lockfiles = [];
  const candidates = [
    ["pnpm", "pnpm-lock.yaml"],
    ["npm", "package-lock.json"],
    ["yarn", "yarn.lock"],
    ["bun", "bun.lock"],
    ["bun", "bun.lockb"],
  ];

  for (const [manager, file] of candidates) {
    if (await pathExists(path.join(root, file))) {
      lockfiles.push({ manager, file });
    }
  }

  let declared = null;
  if (typeof packageJson?.packageManager === "string") {
    declared = packageJson.packageManager.split("@")[0];
  }

  const lockManagers = [...new Set(lockfiles.map((entry) => entry.manager))];
  return {
    packageJson,
    declared,
    lockfiles,
    authoritative: declared ?? (lockManagers.length === 1 ? lockManagers[0] : null),
  };
}

function packageManagerFindings(instructions, metadata, config) {
  const findings = [];
  const usages = [];

  for (const file of instructions) {
    for (const directive of file.directives) {
      if (directive.polarity === "negative") continue;
      for (const manager of directive.packageManagers) {
        usages.push({ manager, file, directive });
      }
    }
  }

  const managers = [...new Set(usages.map((entry) => entry.manager))];
  if (managers.length > 1) {
    const severity = ruleSeverity("package-manager-conflict", config);
    if (severity) {
      findings.push(
        finding(
          "package-manager-conflict",
          severity,
          `Instructions require multiple package managers: ${managers.join(", ")}.`,
          usages.map((entry) => lineId(entry.file, entry.directive.line)),
          {
            evidence: usages
              .map((entry) => `${entry.file.path}:${entry.directive.line} "${entry.manager}"`)
              .join("\n"),
            suggestion: "Choose one repository-wide package manager, or scope each rule to a workspace.",
          },
        ),
      );
    }
  }

  if (metadata.authoritative) {
    const mismatch = usages.filter((entry) => entry.manager !== metadata.authoritative);
    if (mismatch.length > 0) {
      const severity = ruleSeverity("package-manager-mismatch", config);
      if (severity) {
        const source = metadata.declared ? "packageManager field" : "lockfile";
        findings.push(
          finding(
            "package-manager-mismatch",
            severity,
            `Instructions use ${[...new Set(mismatch.map((entry) => entry.manager))].join(", ")}, but the ${source} selects ${metadata.authoritative}.`,
            mismatch.map((entry) => lineId(entry.file, entry.directive.line)),
            {
              evidence: mismatch
                .map((entry) => `${entry.file.path}:${entry.directive.line} uses ${entry.manager}`)
                .join("\n"),
              suggestion: `Use ${metadata.authoritative} consistently, or update the repository metadata.`,
            },
          ),
        );
      }
    }
  }

  return findings;
}

function formattingFindings(instructions, config) {
  const findings = [];
  const entries = [];
  for (const file of instructions) {
    for (const directive of file.directives) {
      if (directive.polarity === "negative") continue;
      for (const value of directive.formatting) {
        entries.push({ value, file, directive });
      }
    }
  }

  const byValue = new Map();
  for (const entry of entries) {
    if (!byValue.has(entry.value)) byValue.set(entry.value, []);
    byValue.get(entry.value).push(entry);
  }

  const conflicts = [
    ["tabs", "spaces", "tabs and spaces are both required"],
    ["2-space", "4-space", "two-space and four-space indentation are both required"],
    ["single-quotes", "double-quotes", "single and double quotes are both required"],
    ["semicolons", "no-semicolons", "semicolons are both required and forbidden"],
  ];

  for (let index = 0; index < FORMATTER_GROUPS.length; index += 1) {
    const group = FORMATTER_GROUPS[index];
    conflicts.push([group[0], group[1], `${group[0]} and ${group[1]} are both required`]);
  }

  for (const [left, right, message] of conflicts) {
    const leftEntries = byValue.get(left) ?? [];
    const rightEntries = byValue.get(right) ?? [];
    if (leftEntries.length === 0 || rightEntries.length === 0) continue;

    const severity = ruleSeverity("format-conflict", config);
    if (!severity) continue;
    const selected = [...leftEntries.slice(0, 2), ...rightEntries.slice(0, 2)];
    findings.push(
      finding(
        "format-conflict",
        severity,
        message.charAt(0).toUpperCase() + message.slice(1) + ".",
        selected.map((entry) => lineId(entry.file, entry.directive.line)),
        {
          evidence: selected
            .map((entry) => `${entry.file.path}:${entry.directive.line} requires ${entry.value}`)
            .join("\n"),
          suggestion: "Keep one formatting authority and let the configured formatter settle the details.",
        },
      ),
    );
  }

  return findings;
}

function pathsOverlap(left, right) {
  const a = toPosixPath(left).replace(/\/+$/, "");
  const b = toPosixPath(right).replace(/\/+$/, "");
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.includes("*") || b.includes("*")) {
    const staticPart = a.includes("*") ? a.slice(0, a.indexOf("*")) : a;
    const otherStatic = b.includes("*") ? b.slice(0, b.indexOf("*")) : b;
    return staticPart.startsWith(otherStatic) || otherStatic.startsWith(staticPart);
  }
  return a.startsWith(`${b}/`) || b.startsWith(`${a}/`);
}

function fileScopeFindings(instructions, config) {
  const entries = [];
  for (const file of instructions) {
    for (const directive of file.directives) {
      if (directive.polarity === "neutral") continue;
      for (const ref of directive.pathRefs) {
        entries.push({ ref, file, directive });
      }
    }
  }

  const findings = [];
  for (let leftIndex = 0; leftIndex < entries.length; leftIndex += 1) {
    const left = entries[leftIndex];
    for (let rightIndex = leftIndex + 1; rightIndex < entries.length; rightIndex += 1) {
      const right = entries[rightIndex];
      if (left.directive.polarity === right.directive.polarity) continue;
      if (!pathsOverlap(left.ref, right.ref)) continue;

      const severity = ruleSeverity("file-scope-conflict", config);
      if (!severity) continue;
      findings.push(
        finding(
          "file-scope-conflict",
          severity,
          `"${left.ref}" is both required and forbidden.`,
          [
            lineId(left.file, left.directive.line),
            lineId(right.file, right.directive.line),
          ],
          {
            evidence: `${left.file.path}:${left.directive.line} ${left.directive.polarity}: ${left.ref}\n${right.file.path}:${right.directive.line} ${right.directive.polarity}: ${right.ref}`,
            suggestion: "Narrow each rule to a distinct path or remove one of the conflicting requirements.",
          },
        ),
      );
    }
  }

  return uniqueBy(findings, (item) => item.message);
}

function testRunnerForCommand(command) {
  const lower = command.toLowerCase();
  if (/\b(?:pytest|python(?:3)? -m pytest)\b/.test(lower)) return "pytest";
  if (/^go\s+test\b/.test(lower)) return "go test";
  if (/^cargo\s+test\b/.test(lower)) return "cargo test";
  if (/^dotnet\s+test\b/.test(lower)) return "dotnet test";
  if (/^(?:npm|pnpm|yarn|bun)\b/.test(lower) && /\btest\b/.test(lower)) return "package test script";
  if (/^(?:jest|vitest|playwright\s+test)\b/.test(lower)) return lower.split(/\s+/)[0];
  return null;
}

function commandFindings(instructions, config) {
  const findings = [];
  const runtimes = [];
  const commitRequirements = [];
  const commitProhibitions = [];

  for (const file of instructions) {
    for (const directive of file.directives) {
      if (directive.polarity !== "negative") {
        for (const command of directive.commands) {
          const runner = testRunnerForCommand(command);
          if (runner) {
            runtimes.push({ runner, command, file, directive });
          }
        }
      }

      if (directive.commitPolicy === "require") {
        commitRequirements.push({ file, directive });
      } else if (directive.commitPolicy === "forbid") {
        commitProhibitions.push({ file, directive });
      }
    }
  }

  const runnerNames = [...new Set(runtimes.map((entry) => entry.runner))];
  if (runnerNames.length > 1) {
    const severity = ruleSeverity("command-conflict", config);
    if (severity) {
      findings.push(
        finding(
          "command-conflict",
          severity,
          `Instructions name multiple test systems: ${runnerNames.join(", ")}.`,
          runtimes.map((entry) => lineId(entry.file, entry.directive.line)),
          {
            evidence: runtimes
              .map((entry) => `${entry.file.path}:${entry.directive.line} ${entry.command}`)
              .join("\n"),
            suggestion: "Name the canonical test command once, then scope workspace-specific commands by path.",
          },
        ),
      );
    }
  }

  if (commitRequirements.length > 0 && commitProhibitions.length > 0) {
    const severity = ruleSeverity("commit-policy-conflict", config);
    if (severity) {
      const selected = [
        ...commitRequirements.slice(0, 2),
        ...commitProhibitions.slice(0, 2),
      ];
      findings.push(
        finding(
          "commit-policy-conflict",
          severity,
          "One instruction requires commits while another forbids them.",
          selected.map((entry) => lineId(entry.file, entry.directive.line)),
          {
            evidence: selected
              .map((entry) => `${entry.file.path}:${entry.directive.line} ${entry.directive.text}`)
              .join("\n"),
            suggestion: "State when an agent may commit and scope the prohibition to the relevant branch or task.",
          },
        ),
      );
    }
  }

  return findings;
}

function makeTargets(source) {
  if (!source) return new Set();
  const targets = new Set();
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z0-9_.-]+)\s*:(?!=)/);
    if (match) targets.add(match[1]);
  }
  return targets;
}

function justRecipes(source) {
  if (!source) return new Set();
  const recipes = new Set();
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^@?([A-Za-z_][A-Za-z0-9_-]*)(?:\s+[^:]*)?:(?!=)/);
    if (match) recipes.add(match[1]);
  }
  return recipes;
}

async function commandReferenceFindings(root, instructions, metadata, config) {
  const findings = [];
  const scripts = metadata.packageJson?.scripts ?? {};
  const makefile = await readTextIfExists(path.join(root, "Makefile"));
  const justfile =
    (await readTextIfExists(path.join(root, "justfile"))) ??
    (await readTextIfExists(path.join(root, "Justfile")));
  const make = makeTargets(makefile);
  const just = justRecipes(justfile);

  for (const file of instructions) {
    for (const directive of file.directives) {
      for (const command of directive.commands) {
        if (command.includes("<") || command.includes(">") || command.includes("$")) {
          continue;
        }

        const packageScript = command.match(
          /^(npm|pnpm|yarn|bun)\s+(?:run\s+|run-script\s+)?([A-Za-z0-9:_-]+)\b/,
        );
        if (
          packageScript &&
          ["npm", "pnpm", "yarn"].includes(packageScript[1]) &&
          !command.includes(" --filter ") &&
          !command.includes("workspace") &&
          !["install", "add", "remove", "exec", "dlx", "create", "init", "ci", "why", "publish"].includes(
            packageScript[2],
          )
        ) {
          const scriptName = packageScript[2];
          if (!Object.hasOwn(scripts, scriptName)) {
            const severity = ruleSeverity("broken-command", config);
            if (severity) {
              findings.push(
                finding(
                  "broken-command",
                  severity,
                  `Command "${command}" points to a missing package.json script "${scriptName}".`,
                  [lineId(file, directive.line)],
                  {
                    evidence: `package.json scripts: ${Object.keys(scripts).join(", ") || "(none)"}`,
                    suggestion: `Add the "${scriptName}" script or update the instruction to an existing command.`,
                  },
                ),
              );
            }
          }
        }

        const makeCommand = command.match(/^make\s+([A-Za-z0-9_.-]+)/);
        if (makeCommand && !make.has(makeCommand[1])) {
          const severity = ruleSeverity("broken-command", config);
          if (severity) {
            findings.push(
              finding(
                "broken-command",
                severity,
                `Command "${command}" points to a missing Makefile target.`,
                [lineId(file, directive.line)],
                {
                  evidence: `Makefile targets: ${[...make].join(", ") || "(none)"}`,
                  suggestion: `Add the "${makeCommand[1]}" target or update the instruction.`,
                },
              ),
            );
          }
        }

        const justCommand = command.match(/^just\s+([A-Za-z0-9_-]+)/);
        if (justCommand && !just.has(justCommand[1])) {
          const severity = ruleSeverity("broken-command", config);
          if (severity) {
            findings.push(
              finding(
                "broken-command",
                severity,
                `Command "${command}" points to a missing just recipe.`,
                [lineId(file, directive.line)],
                {
                  evidence: `just recipes: ${[...just].join(", ") || "(none)"}`,
                  suggestion: `Add the "${justCommand[1]}" recipe or update the instruction.`,
                },
              ),
            );
          }
        }

        if (/^(?:\.{0,2}\/|scripts\/|tools\/)[^\s]+$/.test(command)) {
          const scriptPath = command.split(/\s+/)[0].replace(/^\.\//, "");
          if (!(await pathExists(path.join(root, scriptPath)))) {
            const severity = ruleSeverity("broken-command", config);
            if (severity) {
              findings.push(
                finding(
                  "broken-command",
                  severity,
                  `Command "${command}" points to a missing script.`,
                  [lineId(file, directive.line)],
                  {
                    evidence: `${scriptPath} does not exist.`,
                    suggestion: "Update the path or add the script to the repository.",
                  },
                ),
              );
            }
          }
        }
      }
    }
  }
  return findings;
}

async function pathReferenceFindings(root, instructions, config) {
  const findings = [];
  for (const file of instructions) {
    for (const directive of file.directives) {
      for (const ref of directive.pathRefs) {
        if (
          ref.includes("://") ||
          ref.startsWith("#") ||
          ref.includes("<") ||
          ref.includes("$") ||
          /[*?]/.test(ref)
        ) {
          if (/[*?]/.test(ref) && (await expandSimpleGlob(root, ref)).length > 0) {
            continue;
          }
          if (/[*?]/.test(ref)) {
            const severity = ruleSeverity("broken-reference", config);
            if (severity) {
              findings.push(
                finding(
                  "broken-reference",
                  severity,
                  `Path pattern "${ref}" matches no files.`,
                  [lineId(file, directive.line)],
                  {
                    evidence: `No repository path matches ${ref}.`,
                    suggestion: "Fix the path or remove the stale reference.",
                  },
                ),
              );
            }
          }
          continue;
        }

        if (!(await pathExists(path.join(root, ref)))) {
          const severity = ruleSeverity("broken-reference", config);
          if (severity) {
            findings.push(
              finding(
                "broken-reference",
                severity,
                `Referenced path "${ref}" does not exist.`,
                [lineId(file, directive.line)],
                {
                  evidence: `${ref} was not found from the repository root.`,
                  suggestion: "Fix the path or remove the stale reference.",
                },
              ),
            );
          }
        }
      }
    }
  }
  return findings;
}

function tokenBudgetFindings(instructions, config) {
  const total = instructions.reduce((sum, file) => sum + file.tokens, 0);
  const warningAt = config.budget?.warning ?? 2500;
  const errorAt = config.budget?.error ?? 5000;
  if (total < warningAt) return [];

  const requestedSeverity = total >= errorAt ? "error" : "warning";
  const configured = ruleSeverity("token-budget", config);
  const override = config.rules?.["token-budget"];
  const severity =
    configured === null
      ? null
      : ["info", "warning", "error"].includes(override)
        ? override
        : requestedSeverity;
  if (!severity) return [];

  return [
    finding(
      "token-budget",
      severity,
      `Agent instructions contain roughly ${total.toLocaleString("en-US")} tokens.`,
      instructions.map((file) => ({ path: file.path, line: 1 })),
      {
        evidence: instructions
          .map((file) => `${file.path}: ~${file.tokens.toLocaleString("en-US")} tokens`)
          .join("\n"),
        suggestion:
          "Move stable reference material into linked documents and keep always-loaded instructions short.",
      },
    ),
  ];
}

function duplicateFindings(instructions, config) {
  const directives = [];
  for (const file of instructions) {
    for (const directive of file.directives) {
      const words = wordSet(directive.text);
      if (words.size >= 5) {
        directives.push({ file, directive, words });
      }
    }
  }

  const groups = [];
  const assigned = new Set();
  for (let leftIndex = 0; leftIndex < directives.length; leftIndex += 1) {
    if (assigned.has(leftIndex)) continue;
    const group = [directives[leftIndex]];
    for (let rightIndex = leftIndex + 1; rightIndex < directives.length; rightIndex += 1) {
      if (assigned.has(rightIndex)) continue;
      if (jaccard(directives[leftIndex].words, directives[rightIndex].words) >= 0.9) {
        group.push(directives[rightIndex]);
        assigned.add(rightIndex);
      }
    }
    if (new Set(group.map((entry) => entry.file.path)).size > 1) {
      groups.push(group);
    }
  }

  const severity = ruleSeverity("duplicate-instruction", config);
  if (!severity) return [];

  return groups.slice(0, 10).map((group) => {
    const tokens = group.reduce(
      (sum, entry) => sum + Math.ceil(entry.directive.text.length / 4),
      0,
    );
    return finding(
      "duplicate-instruction",
      severity,
      `The same instruction appears in ${group.length} files (~${tokens} repeated tokens).`,
      group.map((entry) => lineId(entry.file, entry.directive.line)),
      {
        evidence: group
          .map((entry) => `${entry.file.path}:${entry.directive.line} ${entry.directive.text}`)
          .join("\n"),
        suggestion: "Keep the rule once in AGENTS.md and link to it from the other agent files.",
      },
    );
  });
}

export async function runChecks(root, instructions, config = {}, mcpFiles = []) {
  if (instructions.length === 0) {
    const severity = ruleSeverity("no-instructions", config);
    const mcpFindings = scanMcpConfigs(mcpFiles, config);
    return severity
      ? [
          finding(
            "no-instructions",
            severity,
            "No agent instruction files were found.",
            [],
            {
              suggestion:
                "Create AGENTS.md with build, test, and repository conventions if coding agents work in this repo.",
            },
          ),
          ...mcpFindings,
        ]
      : mcpFindings;
  }

  const metadata = await repositoryPackageMetadata(root);
  const findings = [
    ...scanSecrets(instructions, config),
    ...scanTextHazards(instructions, config),
    ...scanMcpConfigs(mcpFiles, config),
    ...packageManagerFindings(instructions, metadata, config),
    ...formattingFindings(instructions, config),
    ...fileScopeFindings(instructions, config),
    ...commandFindings(instructions, config),
    ...(await commandReferenceFindings(root, instructions, metadata, config)),
    ...(await pathReferenceFindings(root, instructions, config)),
    ...tokenBudgetFindings(instructions, config),
    ...duplicateFindings(instructions, config),
  ];

  return findings;
}
