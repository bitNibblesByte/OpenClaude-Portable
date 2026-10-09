/* PacketBlocks UI controller. */

let workspace = null;
let lastCaptureStacks = [];

function toast(msg, kind = "info") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = "toast " + kind;
  el.hidden = false;
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.hidden = true), 3500);
}

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg;
    try { msg = (await res.json()).error; } catch { msg = res.statusText; }
    throw new Error(msg || ("HTTP " + res.status));
  }
  return res;
}

function hexdump(hex) {
  const bytes = hex.match(/../g) || [];
  let out = "";
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const off = i.toString(16).padStart(4, "0");
    const hexpart = chunk.join(" ").padEnd(16 * 3 - 1, " ");
    const ascii = chunk.map((b) => {
      const n = parseInt(b, 16);
      return n >= 32 && n < 127 ? String.fromCharCode(n) : ".";
    }).join("");
    out += `${off}  ${hexpart}  ${ascii}\n`;
  }
  return out || "(empty)";
}

function currentStack() {
  return PacketBlocks.workspaceToStack(workspace);
}

async function buildPacket() {
  const stack = currentStack();
  if (!stack.length) { toast("Drag some protocol blocks onto the canvas first.", "warn"); return; }
  try {
    const res = await api("/api/build", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stack }),
    });
    const data = await res.json();
    document.getElementById("summary").textContent = data.summary + `  (${data.length} bytes)`;
    document.getElementById("hexdump").textContent = hexdump(data.hex);
    const layers = document.getElementById("layers");
    layers.innerHTML = "";
    data.layers.forEach((l) => {
      const div = document.createElement("div");
      div.className = "layer-chip";
      div.innerHTML = `<strong>${l.proto}</strong>` +
        (l.decoded ? `<span class="decoded">${JSON.stringify(l.decoded)}</span>` : "");
      layers.appendChild(div);
    });
  } catch (e) { toast("Build failed: " + e.message, "error"); }
}

async function importPcap(file) {
  const fd = new FormData();
  fd.append("file", file);
  try {
    const res = await api("/api/import-pcap", { method: "POST", body: fd });
    const data = await res.json();
    lastCaptureStacks = data.packets.map((p) => p.stack || []);
    const list = document.getElementById("capture-list");
    list.innerHTML = "";
    data.packets.forEach((p, idx) => {
      const li = document.createElement("li");
      li.textContent = `#${idx + 1}  ${p.summary || p.error || "?"}`;
      li.onclick = () => {
        PacketBlocks.stackToWorkspace(workspace, p.stack || []);
        toast(`Loaded packet #${idx + 1} into the canvas.`);
      };
      list.appendChild(li);
    });
    document.getElementById("capture-count").textContent =
      `${data.count} shown / ${data.total_in_file} in file`;
    document.getElementById("capture-panel").hidden = false;
    toast(`Imported ${data.count} packets.`, "ok");
  } catch (e) { toast("Import failed: " + e.message, "error"); }
}

async function exportPcap() {
  // Export either the imported capture (if present) or the current single packet.
  const stacks = lastCaptureStacks.length ? lastCaptureStacks : [currentStack()];
  const nonEmpty = stacks.filter((s) => s && s.length);
  if (!nonEmpty.length) { toast("Nothing to export.", "warn"); return; }
  try {
    const res = await api("/api/export-pcap", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stacks: nonEmpty }),
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "packetblocks_export.pcap"; a.click();
    URL.revokeObjectURL(url);
    toast(`Exported ${nonEmpty.length} packet(s).`, "ok");
  } catch (e) { toast("Export failed: " + e.message, "error"); }
}

/* ----------------------------- Fuzzing UI ----------------------------- */

function addFuzzRuleRow() {
  const stack = currentStack();
  const cat = PacketBlocks.getCatalogue();
  const container = document.getElementById("fuzz-rules");
  const row = document.createElement("div");
  row.className = "fuzz-rule";

  const layerSel = document.createElement("select");
  stack.forEach((l, i) => {
    const o = document.createElement("option");
    o.value = i; o.textContent = `${i}: ${l.proto}`;
    layerSel.appendChild(o);
  });

  const fieldSel = document.createElement("select");
  const stratSel = document.createElement("select");
  ["boundary", "random", "bitflip", "increment", "wordlist", "string_len"]
    .forEach((s) => { const o = document.createElement("option"); o.value = o.textContent = s; stratSel.appendChild(o); });

  const extra = document.createElement("input");
  extra.placeholder = "values (comma-sep) / step / fill";
  extra.className = "fuzz-extra";

  function refreshFields() {
    fieldSel.innerHTML = "";
    const proto = stack[layerSel.value]?.proto;
    (cat[proto]?.fields || []).forEach((f) => {
      const o = document.createElement("option");
      o.value = f.name; o.textContent = f.label || f.name;
      fieldSel.appendChild(o);
    });
  }
  layerSel.onchange = refreshFields;
  refreshFields();

  const del = document.createElement("button");
  del.textContent = "✕"; del.className = "small"; del.onclick = () => row.remove();

  [layerSel, fieldSel, stratSel, extra, del].forEach((e) => row.appendChild(e));
  container.appendChild(row);
}

function collectFuzzRules() {
  const rows = document.querySelectorAll("#fuzz-rules .fuzz-rule");
  const rules = [];
  rows.forEach((row) => {
    const [layer, field, strat, extra] = row.querySelectorAll("select, input");
    const rule = { layer: Number(layer.value), field: field.value, strategy: strat.value };
    const ex = extra.value.trim();
    if (strat.value === "wordlist" && ex) rule.values = ex.split(",").map((x) => x.trim());
    if (strat.value === "increment" && ex) rule.step = Number(ex) || 1;
    if (strat.value === "string_len" && ex) rule.fill = ex;
    rules.push(rule);
  });
  return rules;
}

async function runFuzz() {
  const stack = currentStack();
  const rules = collectFuzzRules();
  if (!stack.length || !rules.length) { toast("Add at least one fuzz rule.", "warn"); return; }
  const count = Number(document.getElementById("fuzz-cases").value) || 20;
  const seedRaw = document.getElementById("fuzz-seed").value;
  const body = { stack, rules, count };
  if (seedRaw) body.seed = Number(seedRaw);
  try {
    const res = await api("/api/fuzz", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    const list = document.getElementById("fuzz-list");
    list.innerHTML = "";
    lastCaptureStacks = data.cases.map((c) => c.stack); // let Export dump the fuzz set
    data.cases.forEach((c, i) => {
      const li = document.createElement("li");
      const muts = (c.mutations || [])
        .map((m) => `L${m.layer}.${m.field}=${m.value}`).join(", ");
      li.innerHTML = `<span class="muts">${muts}</span>` +
        `<span class="fsum">${c.summary || c.error || ""}</span>`;
      li.onclick = () => PacketBlocks.stackToWorkspace(workspace, c.stack);
      list.appendChild(li);
    });
    document.getElementById("fuzz-count").textContent = data.count + " cases";
    document.getElementById("fuzz-results-panel").hidden = false;
    document.getElementById("fuzz-modal").hidden = true;
    toast(`Generated ${data.count} fuzz cases. Export pcap to save them, or click one to inspect.`, "ok");
  } catch (e) { toast("Fuzz failed: " + e.message, "error"); }
}

async function sendPackets() {
  const stacks = lastCaptureStacks.length ? lastCaptureStacks : [currentStack()];
  const nonEmpty = stacks.filter((s) => s && s.length);
  if (!nonEmpty.length) { toast("Nothing to send.", "warn"); return; }
  if (!confirm(`Send ${nonEmpty.length} packet(s) on the wire?\n\n` +
      `Only do this on networks and devices you own or are authorized to test.`)) return;
  let iface = null;
  try {
    const ir = await (await api("/api/interfaces")).json();
    iface = prompt("Interface to send on:", (ir.interfaces || [])[0] || "eth0");
    if (iface === null) return;
  } catch { /* fall through with null iface */ }
  try {
    const res = await api("/api/send", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stacks: nonEmpty, iface, count: 1 }),
    });
    const data = await res.json();
    toast(`Sent ${data.sent} frame(s) on ${data.iface || "default"}.`, "ok");
  } catch (e) { toast("Send: " + e.message, "error"); }
}

/* ------------------------------- Boot -------------------------------- */

async function boot() {
  const cat = await (await api("/api/protocols")).json();
  PacketBlocks.defineBlocks(cat);
  const toolboxXml = PacketBlocks.toolboxXml(cat);
  workspace = Blockly.inject("blockly-div", {
    toolbox: Blockly.utils.xml.textToDom(toolboxXml),
    grid: { spacing: 22, length: 3, colour: "#eee", snap: true },
    zoom: { controls: true, wheel: true, startScale: 0.95 },
    trashcan: true,
    renderer: "zelos", // the rounded, Scratch-like renderer
  });

  // A friendly starter stack.
  PacketBlocks.stackToWorkspace(workspace, [
    { proto: "Ether", fields: {} },
    { proto: "IP", fields: { src: "10.0.0.1", dst: "10.0.0.2" } },
    { proto: "TCP", fields: { dport: 80, flags: ["S"] } },
  ]);

  document.getElementById("btn-build").onclick = buildPacket;
  document.getElementById("btn-export").onclick = exportPcap;
  document.getElementById("btn-send").onclick = sendPackets;
  document.getElementById("pcap-input").onchange = (e) => {
    if (e.target.files[0]) importPcap(e.target.files[0]);
  };
  document.getElementById("btn-fuzz").onclick = () => {
    document.getElementById("fuzz-rules").innerHTML = "";
    addFuzzRuleRow();
    document.getElementById("fuzz-modal").hidden = false;
  };
  document.getElementById("add-rule").onclick = addFuzzRuleRow;
  document.getElementById("fuzz-cancel").onclick = () =>
    (document.getElementById("fuzz-modal").hidden = true);
  document.getElementById("fuzz-run").onclick = runFuzz;

  buildPacket();
}

window.addEventListener("load", boot);
