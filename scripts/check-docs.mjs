#!/usr/bin/env node
/**
 * Resolve every [[wikilink]] in the docs vault the way Obsidian would.
 *
 * Broken links are the failure mode of a hand-maintained vault: renaming a note or
 * editing a heading silently orphans every link into it, and nothing complains
 * until someone follows one. `pnpm docs:check` makes that a build failure.
 *
 * Matches Obsidian's actual behaviour:
 *   - links inside fenced or inline code are not links
 *   - a wikilink may not span a line break (it renders as literal text instead,
 *     which looks fine in source and is easy to miss)
 *   - inside a table the alias pipe is escaped as `\|`
 *   - a link resolves by note basename or by a frontmatter alias
 *
 *   node scripts/check-docs.mjs [vaultDir] [--debug]
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const vault = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : 'docs';
const debug = process.argv.includes('--debug');

const files = [];
(function walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith('.')) continue; // .obsidian, .trash
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) walk(full);
    else if (entry.endsWith('.md')) files.push(full);
  }
})(vault);

/** Blank out code spans and fences, preserving offsets and line count. */
const stripCode = (text) =>
  text
    .replace(/```[\s\S]*?```/g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/`[^`\n]*`/g, (m) => ' '.repeat(m.length));

// name (basename or alias) -> note record
const notes = new Map();
for (const file of files) {
  const text = readFileSync(file, 'utf8');
  const base = path.basename(file, '.md');
  const headings = new Set(
    [...text.matchAll(/^#{1,6}\s+(.+?)\s*$/gm)].map((m) => m[1].replace(/\s+/g, ' ').trim()),
  );
  const record = { file, base, headings };

  if (notes.has(base) && notes.get(base).base === base) {
    console.log(`  DUPLICATE    two notes named "${base}": ${notes.get(base).file} and ${file}`);
  }
  notes.set(base, record);

  const frontmatter = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  const aliasLine = frontmatter && /^aliases:\s*\[(.*)\]/m.exec(frontmatter[1]);
  if (aliasLine) {
    for (const alias of aliasLine[1].split(',').map((s) => s.trim().replace(/^["']|["']$/g, ''))) {
      // A real note name always wins over an alias.
      if (alias && !notes.has(alias)) notes.set(alias, record);
    }
  }
}

if (debug) {
  for (const [name, note] of [...notes].sort()) {
    console.log(`  ${name.padEnd(46)} ${path.relative(vault, note.file)} (${note.headings.size} headings)`);
  }
  console.log('');
}

let broken = 0;
let total = 0;
const report = (kind, rel, detail) => {
  console.log(`  ${kind}  ${rel}  ->  ${detail}`);
  broken += 1;
};

for (const file of files) {
  const raw = readFileSync(file, 'utf8');
  const text = stripCode(raw);
  const rel = path.relative(vault, file);

  for (const m of stripCode(raw).matchAll(/\[\[[^\[\]]*\n[^\[\]]*\]\]/g)) {
    report('WRAPPED LINK', rel, `${m[0].replace(/\s+/g, ' ').slice(0, 64)}… — cannot span lines`);
  }

  for (const m of text.matchAll(/\[\[([^\[\]\n]+)\]\]/g)) {
    total += 1;
    const inner = m[1].replace(/\\\|/g, '|'); // table-escaped alias pipe
    const targetPart = inner.split('|')[0].trim();
    const [target, heading] = targetPart.split('#').map((s) => (s ?? '').trim());
    const noteName = target || path.basename(file, '.md');
    const note = notes.get(noteName);

    if (!note) {
      report('BROKEN NOTE ', rel, `[[${targetPart}]]`);
      continue;
    }
    if (heading && !note.headings.has(heading.replace(/\s+/g, ' ').trim())) {
      report('BROKEN HEAD ', rel, `[[${noteName}#${heading}]]`);
    }
  }
}

console.log(`\n${files.length} notes, ${total} wikilinks, ${broken} broken`);
process.exit(broken > 0 ? 1 : 0);
