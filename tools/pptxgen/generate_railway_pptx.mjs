import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import PptxGenJS from "pptxgenjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..", "..");
const CSV_PATH = path.join(ROOT, "RAILWAY_PRESENTATION_SLIDES.csv");
const OUT_PATH = path.join(ROOT, "RAILWAY_PRESENTATION_SLIDES.pptx");

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];

    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
      continue;
    }

    if (c === '"') {
      inQuotes = true;
      continue;
    }

    if (c === ",") {
      row.push(field);
      field = "";
      continue;
    }

    if (c === "\r") continue;

    if (c === "\n") {
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
      continue;
    }

    field += c;
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  const header = rows.shift() || [];
  const out = [];
  for (const r of rows) {
    if (r.length === 1 && String(r[0] || "").trim() === "") continue;
    const obj = {};
    for (let i = 0; i < header.length; i++) obj[header[i]] = r[i] ?? "";
    out.push(obj);
  }
  return out;
}

function safeText(s) {
  return String(s ?? "").replace(/\s+/g, " ").trim();
}

async function main() {
  if (!fs.existsSync(CSV_PATH)) {
    console.error("CSV not found:", CSV_PATH);
    process.exit(1);
  }

  const csv = fs.readFileSync(CSV_PATH, "utf8");
  const slides = parseCsv(csv);

  const pptx = new PptxGenJS();
  pptx.layout = "LAYOUT_WIDE";
  pptx.author = "APDS";
  pptx.company = "APDS";
  pptx.subject = "APDS Railway Deployment";
  pptx.title = "APDS Deployment on Railway";

  const theme = {
    bg: "05070F",
    panel: "101827",
    text: "E5E7EB",
    muted: "B6BDC8",
    accent: "7E57C2"
  };

  for (const s of slides) {
    const title = safeText(s["Title"]);
    const bullets = [];
    for (let i = 1; i <= 6; i++) {
      const b = safeText(s[`Bullet ${i}`]);
      if (b) bullets.push(b);
    }
    const notes = String(s["Speaker Notes"] ?? "").trim();

    const slide = pptx.addSlide();
    slide.background = { color: theme.bg };

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.6,
      y: 0.55,
      w: 12.13,
      h: 0.75,
      fill: { color: theme.panel, transparency: 15 },
      line: { color: theme.accent, transparency: 55 }
    });

    slide.addText(title || "Slide", {
      x: 0.85,
      y: 0.68,
      w: 11.6,
      h: 0.5,
      fontFace: "Calibri",
      fontSize: 28,
      bold: true,
      color: theme.text
    });

    const bulletText = bullets.length ? bullets.map((b) => `• ${b}`).join("\n") : "";

    slide.addShape(pptx.ShapeType.roundRect, {
      x: 0.6,
      y: 1.55,
      w: 12.13,
      h: 5.1,
      fill: { color: theme.panel, transparency: 20 },
      line: { color: "FFFFFF", transparency: 85 }
    });

    slide.addText(bulletText, {
      x: 0.95,
      y: 1.8,
      w: 11.4,
      h: 4.6,
      fontFace: "Calibri",
      fontSize: 20,
      color: theme.text,
      valign: "top",
      lineSpacingMultiple: 1.15
    });

    slide.addText("APDS • Railway Deployment", {
      x: 0.6,
      y: 7.0,
      w: 12.13,
      h: 0.3,
      fontFace: "Calibri",
      fontSize: 12,
      color: theme.muted
    });

    if (notes) slide.addNotes(notes);
  }

  await pptx.writeFile({ fileName: OUT_PATH });
  console.log("Wrote:", OUT_PATH);
}

main().catch((e) => {
  console.error(String(e?.stack || e));
  process.exit(1);
});

