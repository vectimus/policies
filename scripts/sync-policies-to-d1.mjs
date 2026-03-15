/**
 * Sync Cedar policies to Cloudflare D1.
 *
 * Parses all .cedar files, extracts annotations, and upserts into the
 * policies table. Updates policy_meta with totals and version info.
 *
 * Auto-discovers packs by scanning for directories containing pack.toml.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

const CLOUDFLARE_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const D1_DATABASE_ID = process.env.D1_DATABASE_ID;

const D1_API = `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/d1/database/${D1_DATABASE_ID}/query`;

if (!CLOUDFLARE_ACCOUNT_ID || !CLOUDFLARE_API_TOKEN || !D1_DATABASE_ID) {
  console.error("Missing required env vars: CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN, D1_DATABASE_ID");
  process.exit(1);
}

// ── Pack discovery ────────────────────────────────────────────────────

const SKIP_DIRS = new Set(["scripts", "node_modules", ".git"]);

async function discoverPacks(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const packs = [];

  for (const entry of entries) {
    if (!entry.isDirectory() || SKIP_DIRS.has(entry.name)) continue;

    const packToml = join(root, entry.name, "pack.toml");
    try {
      await stat(packToml);
      packs.push(entry.name);
    } catch {
      // Not a pack directory
    }
  }

  return packs.sort();
}

// ── Cedar parsing (same logic as generate-policy-index.mjs) ──────────

function extractAnnotation(block, name) {
  const regex = new RegExp(`@${name}\\("([^"]*(?:"[^)]*)*)"\\)`);
  const match = block.match(regex);
  if (match) return match[1];

  const regex2 = new RegExp(`@${name}\\(("(?:[^"\\\\]|\\\\.)*")\\)`);
  const match2 = block.match(regex2);
  if (match2) {
    try {
      return JSON.parse(match2[1]);
    } catch {
      return match2[1].slice(1, -1);
    }
  }
  return null;
}

function parsePolicies(source, pack, file) {
  const policies = [];
  const positions = [];
  const idRegex = /^@id\(/gm;
  let match;
  while ((match = idRegex.exec(source)) !== null) {
    positions.push(match.index);
  }

  for (let i = 0; i < positions.length; i++) {
    const start = positions[i];
    const end = i + 1 < positions.length ? positions[i + 1] : source.length;
    const block = source.slice(start, end).trim();

    const id = extractAnnotation(block, "id");
    if (!id) continue;

    const description = extractAnnotation(block, "description");
    const incident = extractAnnotation(block, "incident");
    const controlsRaw = extractAnnotation(block, "controls");
    const suggestedAlternative = extractAnnotation(block, "suggested_alternative");
    const category = extractAnnotation(block, "category");

    const controls = controlsRaw
      ? JSON.stringify(controlsRaw.split(",").map((c) => c.trim()).filter(Boolean))
      : null;

    const actionMatch = block.match(/Vectimus::Action::"([^"]+)"/);
    const actionType = actionMatch ? actionMatch[1] : null;

    const likeMatches = block.match(/\blike\s+"/g);
    const ruleCount = likeMatches ? likeMatches.length : 0;

    policies.push({
      id,
      pack,
      file,
      description: description || null,
      incident: incident || null,
      category: category || null,
      controls,
      suggested_alternative: suggestedAlternative || null,
      action_type: actionType,
      rule_count: ruleCount,
      source: block,
    });
  }

  return policies;
}

// ── D1 API helpers ───────────────────────────────────────────────────

async function d1Execute(sql, params = []) {
  const res = await fetch(D1_API, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ sql, params }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`D1 API error ${res.status}: ${text}`);
  }

  const data = await res.json();
  if (!data.success) {
    throw new Error(`D1 query failed: ${JSON.stringify(data.errors)}`);
  }

  return data.result?.[0]?.results ?? [];
}

// ── Main ─────────────────────────────────────────────────────────────

async function main() {
  const packDirs = await discoverPacks(".");
  console.log(`Discovered packs: ${packDirs.join(", ")}`);

  const allPolicies = [];

  for (const pack of packDirs) {
    let entries;
    try {
      entries = await readdir(pack);
    } catch {
      console.log(`  Pack directory ${pack} not found, skipping`);
      continue;
    }

    const cedarFiles = entries.filter((f) => f.endsWith(".cedar")).sort();
    for (const file of cedarFiles) {
      const content = await readFile(join(pack, file), "utf-8");
      const policies = parsePolicies(content, pack, file);
      allPolicies.push(...policies);
    }
  }

  console.log(`Parsed ${allPolicies.length} policies`);

  // Read version
  let version = "unknown";
  try {
    version = (await readFile("VERSION", "utf-8")).trim();
  } catch {
    console.log("  No VERSION file found");
  }

  const now = new Date().toISOString();

  // Upsert each policy
  for (const p of allPolicies) {
    await d1Execute(
      `INSERT OR REPLACE INTO policies
       (id, pack, file, description, incident, category, controls, suggested_alternative, action_type, rule_count, source, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [p.id, p.pack, p.file, p.description, p.incident, p.category, p.controls, p.suggested_alternative, p.action_type, p.rule_count, p.source, now, now]
    );
  }

  // Delete policies that no longer exist in source
  const existingIds = allPolicies.map((p) => p.id);
  const dbPolicies = await d1Execute("SELECT id FROM policies");
  const toDelete = dbPolicies.filter((row) => !existingIds.includes(row.id));
  for (const row of toDelete) {
    await d1Execute("DELETE FROM policies WHERE id = ?", [row.id]);
    console.log(`  Deleted stale policy: ${row.id}`);
  }

  // Total rules
  const totalRules = allPolicies.reduce((sum, p) => sum + p.rule_count, 0);

  // Packs summary
  const packs = {};
  for (const p of allPolicies) {
    packs[p.pack] = (packs[p.pack] || 0) + 1;
  }

  // Update policy_meta
  const metaEntries = [
    ["total_policies", String(allPolicies.length)],
    ["total_rules", String(totalRules)],
    ["packs", JSON.stringify(packs)],
    ["version", version],
    ["synced_at", now],
  ];
  for (const [key, value] of metaEntries) {
    await d1Execute(
      "INSERT OR REPLACE INTO policy_meta (key, value) VALUES (?, ?)",
      [key, value]
    );
  }

  console.log(`Synced ${allPolicies.length} policies (${totalRules} rules) — version ${version}`);
  console.log(`Packs: ${JSON.stringify(packs)}`);
  if (toDelete.length > 0) {
    console.log(`Removed ${toDelete.length} stale policies`);
  }
}

main().catch((err) => {
  console.error("Sync failed:", err);
  process.exit(1);
});
