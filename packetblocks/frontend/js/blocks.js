/*
 * Generates Blockly block definitions from the protocol catalogue served by the
 * backend, and provides helpers to (de)serialize the stacked blocks to/from the
 * JSON "block stack" format the API speaks.
 *
 * Each protocol becomes one block that connects top-and-bottom (Scratch style),
 * so dragging IP under Ether under nothing builds the stack top-down. Category
 * colour comes straight from the registry.
 */

const PacketBlocks = (() => {
  let catalogue = {};

  function fieldToBlocklyField(block, f) {
    const name = f.name.toUpperCase();
    const label = f.label || f.name;
    switch (f.type) {
      case "int":
        block.appendDummyInput()
          .appendField(label)
          .appendField(new Blockly.FieldNumber(f.default ?? 0), name);
        break;
      case "enum": {
        const opts = (f.options || []).map(([v, l]) => [l, String(v)]);
        block.appendDummyInput()
          .appendField(label)
          .appendField(new Blockly.FieldDropdown(opts.length ? opts : [["-", "0"]]), name);
        break;
      }
      case "flags": {
        const inp = block.appendDummyInput().appendField(label + ":");
        (f.options || []).forEach(([v]) => {
          const on = (f.default || []).includes(v);
          inp.appendField(v, "LBL_" + v)
             .appendField(new Blockly.FieldCheckbox(on ? "TRUE" : "FALSE"), "FLAG_" + v);
        });
        break;
      }
      case "bytes":
      case "str":
      case "ip":
      case "mac":
      default:
        block.appendDummyInput()
          .appendField(label)
          .appendField(new Blockly.FieldTextInput(String(f.default ?? "")), name);
        break;
    }
  }

  function defineBlocks(cat) {
    catalogue = cat;
    Object.values(cat).forEach((spec) => {
      const type = "pb_" + spec.name;
      Blockly.Blocks[type] = {
        init() {
          this.appendDummyInput()
            .appendField("📦 " + (spec.label || spec.name));
          (spec.fields || []).forEach((f) => fieldToBlocklyField(this, f));
          this.setPreviousStatement(true, null);
          this.setNextStatement(true, null);
          this.setColour(spec.color || "#888");
          this.setTooltip(spec.help || spec.label || spec.name);
          this.pbProto = spec.name;
          this.pbFamily = spec.family;
        },
      };
    });
  }

  // Build the toolbox XML grouped by category.
  function toolboxXml(cat) {
    const cats = {};
    Object.values(cat).forEach((spec) => {
      (cats[spec.category] = cats[spec.category] || []).push(spec);
    });
    let xml = '<xml id="toolbox" style="display:none">';
    Object.keys(cats).forEach((category) => {
      const colour = cats[category][0].color || "#888";
      xml += `<category name="${category}" colour="${colour}">`;
      cats[category].forEach((spec) => {
        xml += `<block type="pb_${spec.name}"></block>`;
      });
      xml += "</category>";
    });
    xml += "</xml>";
    return xml;
  }

  // Serialize one block -> {proto, fields}
  function blockToLayer(block) {
    const spec = catalogue[block.pbProto];
    const fields = {};
    (spec.fields || []).forEach((f) => {
      const name = f.name.toUpperCase();
      if (f.type === "flags") {
        const chosen = [];
        (f.options || []).forEach(([v]) => {
          if (block.getFieldValue("FLAG_" + v) === "TRUE") chosen.push(v);
        });
        fields[f.name] = chosen;
      } else if (f.type === "enum") {
        const raw = block.getFieldValue(name);
        const n = Number(raw);
        fields[f.name] = Number.isNaN(n) ? raw : n;
      } else {
        fields[f.name] = block.getFieldValue(name);
      }
    });
    return { proto: block.pbProto, fields };
  }

  // Walk the top-most stack in the workspace into a block stack.
  function workspaceToStack(workspace) {
    const tops = workspace.getTopBlocks(true).filter((b) => b.pbProto);
    if (!tops.length) return [];
    // Choose the stack whose head has no previous connection target: the first.
    let head = tops[0];
    const stack = [];
    let cur = head;
    while (cur) {
      if (cur.pbProto) stack.push(blockToLayer(cur));
      cur = cur.getNextBlock();
    }
    return stack;
  }

  // Build blocks in the workspace from a block stack (used when loading a capture).
  function stackToWorkspace(workspace, stack) {
    workspace.clear();
    let prev = null;
    stack.forEach((layer) => {
      const type = "pb_" + layer.proto;
      if (!Blockly.Blocks[type]) return;
      const block = workspace.newBlock(type);
      const spec = catalogue[layer.proto];
      (spec.fields || []).forEach((f) => {
        const val = layer.fields ? layer.fields[f.name] : undefined;
        if (val === undefined || val === null) return;
        const name = f.name.toUpperCase();
        if (f.type === "flags") {
          (f.options || []).forEach(([v]) => {
            const field = block.getField("FLAG_" + v);
            if (field) field.setValue((val || []).includes(v) ? "TRUE" : "FALSE");
          });
        } else {
          const field = block.getField(name);
          if (field) field.setValue(String(val));
        }
      });
      block.initSvg();
      block.render();
      if (prev && prev.nextConnection && block.previousConnection) {
        prev.nextConnection.connect(block.previousConnection);
      }
      prev = block;
    });
  }

  return { defineBlocks, toolboxXml, workspaceToStack, stackToWorkspace,
           getCatalogue: () => catalogue };
})();
