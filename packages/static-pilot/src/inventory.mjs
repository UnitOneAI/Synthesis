import { unzipSync, strFromU8 } from "fflate";
import { XMLParser, XMLValidator } from "fast-xml-parser";
import path from "node:path";

export const MAX_UPLOAD = 12 * 1024 * 1024;
export function parseXml(text) {
  if (/<!DOCTYPE|<!ENTITY/i.test(text))
    throw new Error("DTD and entity declarations are not supported");
  if (XMLValidator.validate(text) !== true) throw new Error("Invalid XML");
  return new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@",
    parseTagValue: false,
    parseAttributeValue: false,
    processEntities: false,
  }).parse(text);
}
export function unzipBounded(bytes, limit = 64 * 1024 * 1024) {
  let total = 0,
    count = 0;
  return unzipSync(bytes, {
    filter(entry) {
      total += entry.originalSize;
      if (++count > 50000 || total > limit || entry.originalSize > limit)
        throw new Error("Archive expansion limit exceeded");
      return true;
    },
  });
}
const array = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);
const xmlText = (x) =>
  typeof x === "object" && x !== null
    ? (x["#text"] ??
      (x.t !== undefined
        ? xmlText(x.t)
        : array(x.r)
            .map((v) => xmlText(v.t))
            .join("")))
    : (x ?? "");
function xlsxRows(bytes) {
  const zip = unzipBounded(bytes);
  const read = (name) => {
    if (!zip[name]) throw new Error(`Workbook entry missing: ${name}`);
    return parseXml(strFromU8(zip[name]));
  };
  const strings = zip["xl/sharedStrings.xml"]
    ? array(read("xl/sharedStrings.xml").sst?.si).map(xmlText)
    : [];
  const sheets = array(read("xl/workbook.xml").workbook?.sheets?.sheet);
  const sheet =
    sheets.find((s) => s["@name"] === "Repository Classification") ?? sheets[0];
  if (!sheet) throw new Error("Workbook contains no sheets");
  const rel = array(
    read("xl/_rels/workbook.xml.rels").Relationships?.Relationship,
  ).find((r) => r["@Id"] === sheet["@r:id"]);
  if (!rel || rel["@TargetMode"] === "External")
    throw new Error("Invalid worksheet relationship");
  const target = rel["@Target"].startsWith("/")
    ? rel["@Target"].slice(1)
    : path.posix.normalize("xl/" + rel["@Target"]);
  if (!target.startsWith("xl/")) throw new Error("Invalid worksheet path");
  return array(read(target).worksheet?.sheetData?.row).map((row) => {
    const cells = [];
    for (const c of array(row.c)) {
      const col = String(c["@r"] ?? "").match(/^[A-Z]+/)?.[0];
      if (!col) continue;
      const index =
        [...col].reduce((n, v) => n * 26 + v.charCodeAt(0) - 64, 0) - 1;
      if (index > 100) continue;
      if (c.f !== undefined)
        throw new Error(
          "Inventory formulas are not accepted; export a values-only CSV",
        );
      cells[index] = String(
        c["@t"] === "s"
          ? (strings[Number(c.v)] ?? "")
          : c["@t"] === "inlineStr"
            ? xmlText(c.is?.t ?? c.is)
            : (c.v ?? ""),
      );
    }
    return cells;
  });
}
export function csvRows(text) {
  const rows = [];
  let row = [],
    value = "",
    quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      if (quoted && text[i + 1] === '"') {
        value += '"';
        i++;
      } else quoted = !quoted;
    } else if (c === "," && !quoted) {
      row.push(value);
      value = "";
    } else if ((c === "\n" || c === "\r") && !quoted) {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(value);
      rows.push(row);
      row = [];
      value = "";
    } else value += c;
  }
  if (quoted) throw new Error("Unclosed CSV quote");
  if (value || row.length) {
    row.push(value);
    rows.push(row);
  }
  return rows;
}
export function parseInventory(bytes, filename) {
  if (bytes.length > MAX_UPLOAD) throw new Error("Inventory exceeds 12 MiB");
  const rows = /\.xlsx$/i.test(filename)
    ? xlsxRows(bytes)
    : csvRows(
        Buffer.from(bytes)
          .toString("utf8")
          .replace(/^\uFEFF/, ""),
      );
  const header = rows.shift()?.map((x) => String(x).trim().toLowerCase()) ?? [];
  const field = (row, key) => String(row[header.indexOf(key)] ?? "").trim();
  if (!header.includes("repository"))
    throw new Error("Inventory needs a Repository column");
  const seen = new Set(),
    warnings = [],
    repositories = [];
  for (const [i, row] of rows.entries()) {
    const name = field(row, "repository");
    if (!name) continue;
    if (seen.has(name.toLowerCase())) {
      warnings.push(`Duplicate repository at row ${i + 2}: ${name}`);
      continue;
    }
    seen.add(name.toLowerCase());
    repositories.push({
      name,
      url: field(row, "url"),
      description: field(row, "description"),
      category: field(row, "primary category"),
      tier: field(row, "threat-modeling tier"),
      originalSelection: /^yes$/i.test(field(row, "recommended initial set")),
      selected: /^yes$/i.test(field(row, "recommended initial set")),
      scope: "primary",
      basis: "inventory declaration",
      row: i + 2,
      localPath: name,
    });
  }
  if (!repositories.length || repositories.length > 1000)
    throw new Error("Inventory must contain 1–1000 repositories");
  return {
    repositories,
    warnings,
    counts: {
      total: repositories.length,
      selected: repositories.filter((r) => r.selected).length,
      missingDescriptions: repositories.filter((r) => !r.description).length,
    },
  };
}
