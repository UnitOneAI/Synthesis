(async () => {
  const params = new URLSearchParams(location.hash.slice(1));
  const key = params.get("token"),
    format = params.get("format");
  history.replaceState(null, "", location.pathname);
  const status = document.getElementById("report-status");
  try {
    if (
      !/^[a-f0-9]{64}$/.test(key || "") ||
      !["threat-print-html", "cwe-evidence-html"].includes(format)
    )
      throw Error("Open the report from the Synthesis workspace.");
    const response = await fetch(
      "/api/export?" + new URLSearchParams({ format }),
      { headers: { "X-Synthesis-Token": key } },
    );
    if (!response.ok) throw Error((await response.json()).error);
    const parsed = new DOMParser().parseFromString(
      await response.text(),
      "text/html",
    );
    document.title = parsed.title;
    for (const style of parsed.head.querySelectorAll("style"))
      document.head.append(style.cloneNode(true));
    document.getElementById("report-content").innerHTML = parsed.body.innerHTML;
    const button = document.getElementById("print-report");
    button.disabled = false;
    button.onclick = () => window.print();
    status.textContent = "Report ready. Select Print / Save as PDF.";
  } catch (error) {
    status.textContent = error.message;
  }
})();
