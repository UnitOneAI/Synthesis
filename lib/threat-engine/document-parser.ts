import path from "path";

/**
 * Extract text content from an uploaded file buffer.
 * Supports .md, .txt, and .pdf files.
 */
export async function extractTextFromFile(
  buffer: Buffer,
  filename: string
): Promise<string> {
  const ext = path.extname(filename).toLowerCase();

  switch (ext) {
    case ".md":
    case ".txt":
    case ".markdown":
      return buffer.toString("utf-8");
    case ".pdf": {
      // Dynamic import — pdf-parse v1 works in Node.js without browser workers
      const pdfParse = (await import("pdf-parse")).default;
      const result = await pdfParse(buffer);
      return result.text;
    }
    default:
      throw new Error(
        `Unsupported file type: ${ext}. Supported formats: .md, .txt, .pdf`
      );
  }
}
