import fs from "node:fs/promises";
import path from "node:path";
import { createRequire } from "node:module";
import { configTemplate } from "./config.js";
import { reportHtml } from "./html-report.js";
import {
  reportGithub,
  reportJson,
  reportMarkdown,
  reportBadge,
  reportPretty,
  reportRules,
  reportSarif,
} from "./reporters.js";
import { scan, shouldFail } from "./scan.js";

const require = createRequire(import.meta.url);
const packageJson = require("../package.json");

const HELP = `Ruleproof ${packageJson.version}

Find contradictory, broken, and unsafe instructions across AGENTS.md,
CLAUDE.md, Cursor rules, Copilot instructions, and MCP configs.

USAGE
  ruleproof [path] [options]
  ruleproof init [path]

OPTIONS
  --format <name>    pretty, json, markdown, github, sarif, html, or badge (default: pretty)
  --output <file>    Write the report to a file
  --config <file>    Use a specific config file
  --fail-on <level>  error, warning, info, or never (default: error)
  --min-score <n>    Fail when the score is below n
  --strict           Alias for --fail-on warning
  --verbose          Include evidence in terminal output
  --no-color         Disable ANSI colors
  --quiet            Suppress the report; use the exit code only
  --list-rules       Print the rule catalog
  --version          Print the version
  --help             Print this help

EXAMPLES
  npx ruleproof
  npx ruleproof . --verbose
  npx ruleproof . --format html --output ruleproof-report.html
  npx ruleproof . --format sarif --output ruleproof.sarif
  npx ruleproof . --format badge --output .github/ruleproof.svg
`;

function parseArguments(argv) {
  const options = {
    target: ".",
    format: "pretty",
    color: undefined,
    verbose: false,
    quiet: false,
  };
  const positional = [];

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg === "--version" || arg === "-v") {
      options.version = true;
    } else if (arg === "--json") {
      options.format = "json";
    } else if (arg === "--format" || arg === "-f") {
      options.format = argv[++index];
    } else if (arg.startsWith("--format=")) {
      options.format = arg.slice("--format=".length);
    } else if (arg === "--output" || arg === "-o") {
      options.output = argv[++index];
    } else if (arg.startsWith("--output=")) {
      options.output = arg.slice("--output=".length);
    } else if (arg === "--config" || arg === "-c") {
      options.config = argv[++index];
    } else if (arg.startsWith("--config=")) {
      options.config = arg.slice("--config=".length);
    } else if (arg === "--fail-on") {
      options.failOn = argv[++index];
    } else if (arg.startsWith("--fail-on=")) {
      options.failOn = arg.slice("--fail-on=".length);
    } else if (arg === "--min-score") {
      options.minScore = Number(argv[++index]);
    } else if (arg.startsWith("--min-score=")) {
      options.minScore = Number(arg.slice("--min-score=".length));
    } else if (arg === "--strict") {
      options.failOn = "warning";
    } else if (arg === "--verbose") {
      options.verbose = true;
    } else if (arg === "--no-color") {
      options.color = false;
    } else if (arg === "--color") {
      options.color = true;
    } else if (arg === "--quiet" || arg === "-q") {
      options.quiet = true;
    } else if (arg === "--list-rules") {
      options.listRules = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      positional.push(arg);
    }
  }

  if (positional.length > 0) {
    options.target = positional[0];
  }
  if (!["pretty", "json", "markdown", "github", "sarif", "html", "badge"].includes(options.format)) {
    throw new Error(`Unknown format: ${options.format}`);
  }
  if (
    options.failOn &&
    !["error", "warning", "info", "never"].includes(options.failOn)
  ) {
    throw new Error(`Invalid --fail-on value: ${options.failOn}`);
  }
  if (options.minScore !== undefined && !Number.isFinite(options.minScore)) {
    throw new Error("--min-score must be a number");
  }
  return options;
}

async function init(target) {
  const root = path.resolve(target);
  const configPath = path.join(root, ".ruleproof.json");
  try {
    await fs.writeFile(configPath, configTemplate(), { flag: "wx" });
    process.stdout.write(`Created ${path.relative(process.cwd(), configPath)}\n`);
  } catch (error) {
    if (error.code === "EEXIST") {
      process.stdout.write(`${path.relative(process.cwd(), configPath)} already exists\n`);
    } else {
      throw error;
    }
  }
  process.stdout.write("Run `npx ruleproof .` to audit the repository.\n");
}

function render(result, options) {
  if (options.format === "json") return reportJson(result);
  if (options.format === "markdown") return reportMarkdown(result);
  if (options.format === "github") return reportGithub(result);
  if (options.format === "sarif") return reportSarif(result);
  if (options.format === "html") return reportHtml(result);
  if (options.format === "badge") return reportBadge(result);
  return reportPretty(result, options);
}

export async function run(argv) {
  if (argv[0] === "init") {
    await init(argv[1] ?? ".");
    return;
  }

  const options = parseArguments(argv);
  if (options.help) {
    process.stdout.write(HELP);
    return;
  }
  if (options.version) {
    process.stdout.write(`${packageJson.version}\n`);
    return;
  }
  if (options.listRules) {
    process.stdout.write(reportRules());
    return;
  }

  const result = await scan(options.target, {
    config: options.config,
    failOn: options.failOn,
    minScore: options.minScore,
    version: packageJson.version,
  });

  if (options.color === undefined) {
    options.color = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
  }

  if (options.format === "html" && !options.output) {
    options.output = "ruleproof-report.html";
  }
  const output = render(result, options);
  if (options.output) {
    await fs.writeFile(path.resolve(options.output), output);
    if (!options.quiet) {
      process.stdout.write(
        `Wrote ${options.output} (score ${result.score}/100, ${result.findings.length} findings)\n`,
      );
    }
  } else if (!options.quiet) {
    process.stdout.write(output);
  }

  process.exitCode = shouldFail(result, {
    failOn: options.failOn,
    minScore: options.minScore,
  })
    ? 1
    : 0;
}
