#!/usr/bin/env node
/**
 * tsast-facts: parse one TS/JS file (compiler API, no typecheck) and emit JSON facts.
 *
 * Usage: node facts.mjs <file.ts>
 * Exit 1 on IO/parse error, 2 on usage error.
 */
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const MAX_SUMMARY = 400;

const REQ_PARAMS = new Set(["req", "request", "ctx", "c"]);
const RES_PARAMS = new Set(["res", "reply", "next"]);
const HTTP_METHODS = new Set([
  "get", "post", "put", "patch", "delete", "del", "use", "all",
  "options", "head", "connect", "trace",
]);
const GLOBAL_ROOTS = new Set(["window", "globalThis", "global", "self"]);

function scriptKind(file) {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".tsx") return ts.ScriptKind.TSX;
  if (ext === ".jsx") return ts.ScriptKind.JSX;
  if (ext === ".js" || ext === ".mjs" || ext === ".cjs") return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function clip(text) {
  if (text.length <= MAX_SUMMARY) return text;
  return text.slice(0, MAX_SUMMARY);
}

function lineOf(sf, pos) {
  return sf.getLineAndCharacterOfPosition(pos).line + 1;
}

function unwrap(node) {
  while (node) {
    if (ts.isParenthesizedExpression(node)
        || ts.isAsExpression(node)
        || ts.isSatisfiesExpression(node)
        || ts.isNonNullExpression(node)
        || ts.isTypeAssertionExpression(node)) {
      node = node.expression;
      continue;
    }
    break;
  }
  return node;
}

function unwrapDeep(node) {
  node = unwrap(node);
  while (node && ts.isAwaitExpression(node)) {
    node = unwrap(node.expression);
  }
  return node;
}

function propName(member) {
  const name = member.name;
  if (!name) return null;
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  return null;
}

function calleeName(expr) {
  const parts = [];
  let cur = unwrap(expr);
  while (cur) {
    if (ts.isIdentifier(cur)) {
      parts.push(cur.text);
      break;
    }
    if (ts.isPropertyAccessExpression(cur)) {
      parts.push(cur.name.text);
      cur = unwrap(cur.expression);
      continue;
    }
    if (ts.isCallExpression(cur)) {
      cur = unwrap(cur.expression);
      continue;
    }
    if (ts.isElementAccessExpression(cur)) {
      cur = unwrap(cur.expression);
      continue;
    }
    if (ts.isNewExpression(cur)) {
      const inner = calleeName(cur.expression);
      return inner ? `new ${inner}` : "";
    }
    break;
  }
  parts.reverse();
  if (parts.length > 3) return parts.slice(-3).join(".");
  return parts.join(".");
}

function containsCall(node) {
  let found = false;
  function walk(n) {
    if (!n || found) return;
    if (ts.isCallExpression(n) || ts.isNewExpression(n)
        || ts.isAwaitExpression(n) || ts.isTaggedTemplateExpression(n)) {
      found = true;
      return;
    }
    ts.forEachChild(n, walk);
  }
  walk(node);
  return found;
}

function firstArgKind(expr) {
  const node = unwrapDeep(expr);
  if (!node) return "other";
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
      || ts.isNumericLiteral(node)) {
    return "string_literal";
  }
  if (ts.isTemplateExpression(node)) return "template";
  if (ts.isIdentifier(node)) return "identifier";
  if (ts.isCallExpression(node)) return "call";
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return "property";
  }
  if (ts.isNewExpression(node)) return "new";
  return "other";
}

function firstArgName(expr) {
  const node = unwrapDeep(expr);
  if (!node) return null;
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isCallExpression(node)) return calleeName(node.expression) || null;
  if (ts.isPropertyAccessExpression(node)) return clip(node.getText());
  if (ts.isNewExpression(node)) return calleeName(node) || null;
  return null;
}

function isFunctionLike(node) {
  return ts.isFunctionDeclaration(node)
    || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node)
    || ts.isMethodDeclaration(node)
    || ts.isConstructorDeclaration(node);
}

function skipThisParam(p) {
  return p.name && p.name.kind === ts.SyntaxKind.ThisKeyword;
}

function paramNames(fn) {
  const out = [];
  for (const p of fn.parameters) {
    if (skipThisParam(p)) continue;
    if (ts.isIdentifier(p.name)) out.push(p.name.text);
  }
  return out;
}

function isHandlerParams(params) {
  const lower = params.map((p) => p.toLowerCase());
  const set = new Set(lower);
  const hasReq = lower.some((p) => REQ_PARAMS.has(p));
  const hasRes = lower.some((p) => RES_PARAMS.has(p));
  const honoC = set.has("c");
  return hasReq && (hasRes || honoC);
}

function functionName(node) {
  if (node.name && ts.isIdentifier(node.name)) return node.name.text;
  if (node.name && ts.isStringLiteral(node.name)) return node.name.text;
  let p = node.parent;
  while (p && ts.isParenthesizedExpression(p)) p = p.parent;
  if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  if (p && ts.isPropertyAssignment(p)) {
    const n = propName(p);
    if (n) return n;
  }
  if (p && ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isIdentifier(p.left)) {
    return p.left.text;
  }
  return null;
}

function peelToCall(node) {
  let p = node.parent;
  while (p && (ts.isParenthesizedExpression(p) || ts.isAsExpression(p)
      || ts.isSatisfiesExpression(p) || ts.isNonNullExpression(p)
      || ts.isTypeAssertionExpression(p))) {
    p = p.parent;
  }
  return p;
}

function isRouteCallback(fn) {
  let p = peelToCall(fn);
  while (p && (ts.isAsExpression(p) || ts.isParenthesizedExpression(p)
      || ts.isSatisfiesExpression(p))) {
    p = p.parent;
  }
  if (!p || !ts.isCallExpression(p)) return false;
  const callee = unwrap(p.expression);
  if (!ts.isPropertyAccessExpression(callee)) return false;
  const method = callee.name.text.toLowerCase();
  if (!HTTP_METHODS.has(method)) return false;
  const first = p.arguments[0];
  if (method === "use" || method === "all") return true;
  if (!first) return false;
  const f = unwrap(first);
  return ts.isStringLiteral(f)
    || ts.isNoSubstitutionTemplateLiteral(f)
    || ts.isTemplateExpression(f);
}

function looksLikeRequest(expr) {
  const node = unwrapDeep(expr);
  if (!node) return false;
  if (ts.isNewExpression(node)) {
    const n = calleeName(node.expression);
    return n === "Request" || n.endsWith(".Request");
  }
  if (ts.isIdentifier(node)) {
    const t = node.text.toLowerCase();
    return t === "request" || t === "req" || t === "input";
  }
  return false;
}

function objectLiteralHasSignalProperty(obj) {
  for (const p of obj.properties) {
    if (ts.isSpreadAssignment(p)) continue;
    if (propName(p) === "signal") return true;
  }
  return false;
}

function parentCallName(node) {
  let p = node.parent;
  while (p && (ts.isParenthesizedExpression(p) || ts.isAwaitExpression(p)
      || ts.isAsExpression(p) || ts.isSatisfiesExpression(p)
      || ts.isNonNullExpression(p) || ts.isTypeAssertionExpression(p))) {
    p = p.parent;
  }
  if (p && ts.isCallExpression(p)) {
    const args = p.arguments || [];
    const isArg = args.some((a) => {
      let cur = a;
      while (cur && cur !== p) {
        if (cur === node) return true;
        cur = cur.parent;
      }
      return false;
    });
    if (isArg) return calleeName(p.expression) || null;
  }
  return null;
}

const JSX_FACTORY_LEAF = new Set([
  "createElement", "jsx", "jsxs", "jsxDEV", "_jsx", "_jsxs", "_jsxDEV",
]);

function callLeaf(name) {
  if (!name) return "";
  const parts = name.split(".");
  return parts[parts.length - 1] || "";
}

function enclosingFunction(node) {
  let p = node.parent;
  while (p) {
    if (isFunctionLike(p)) return p;
    p = p.parent;
  }
  return null;
}

function jsxTagName(el) {
  const t = el.tagName;
  if (!t) return "";
  if (ts.isIdentifier(t)) return t.text;
  if (ts.isPropertyAccessExpression(t)) return clip(t.getText());
  if (typeof ts.isJsxNamespacedName === "function" && ts.isJsxNamespacedName(t)) {
    return `${t.namespace.text}:${t.name.text}`;
  }
  return clip(t.getText());
}

function jsxAttrName(attr) {
  const n = attr.name;
  if (!n) return "";
  if (ts.isIdentifier(n)) return n.text;
  if (typeof ts.isJsxNamespacedName === "function" && ts.isJsxNamespacedName(n)) {
    return `${n.namespace.text}:${n.name.text}`;
  }
  return clip(n.getText());
}

function exprKey(node) {
  const n = unwrapDeep(node);
  if (!n) return "";
  if (ts.isIdentifier(n)) return `id:${n.text}`;
  return `txt:${n.getText().replace(/\s+/g, "")}`;
}

function classifyExpr(expr) {
  const node = unwrapDeep(expr);
  if (!node) return { kind: "other", value_summary: "" };
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
      || ts.isNumericLiteral(node)) {
    return { kind: "string_literal", value_summary: node.text };
  }
  if (ts.isTemplateExpression(node)) {
    return { kind: "template", value_summary: node.head.text };
  }
  if (ts.isIdentifier(node)) {
    return { kind: "identifier", value_summary: node.text };
  }
  if (ts.isCallExpression(node)) {
    return { kind: "call", value_summary: clip(node.getText()) };
  }
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return { kind: "property", value_summary: clip(node.getText()) };
  }
  return { kind: "other", value_summary: clip(node.getText()) };
}

function isHttpSchemeLiteral(node) {
  if (!node) return false;
  const n = unwrapDeep(node);
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
    return n.text.toLowerCase().startsWith("http");
  }
  return false;
}

function isHttpSchemeRegex(node) {
  if (!node || !ts.isRegularExpressionLiteral(node)) return false;
  return node.text.includes("http");
}

function hasSchemeAllowlist(fn, expr) {
  if (!fn || !expr) return false;
  const key = exprKey(expr);
  const root = unwrapDeep(expr);
  const id = root && ts.isIdentifier(root) ? root.text : null;
  let found = false;

  function matchesTarget(target) {
    if (!target) return false;
    if (exprKey(target) === key) return true;
    const t = unwrapDeep(target);
    return !!(id && t && ts.isIdentifier(t) && t.text === id);
  }

  function walk(n) {
    if (!n || found) return;
    if (ts.isCallExpression(n)) {
      const callee = unwrap(n.expression);
      if (ts.isPropertyAccessExpression(callee) && callee.name.text === "startsWith") {
        if (isHttpSchemeLiteral(n.arguments[0]) && matchesTarget(callee.expression)) {
          found = true;
          return;
        }
      }
      if (ts.isPropertyAccessExpression(callee) && callee.name.text === "test") {
        const recv = unwrapDeep(callee.expression);
        if (isHttpSchemeRegex(recv) && n.arguments[0] && matchesTarget(n.arguments[0])) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(n, walk);
  }
  walk(fn);
  return found;
}

function inspectEffectFn(fn) {
  const out = {
    has_timeout: false,
    has_interval: false,
    has_cleanup_timer: false,
    has_cleanup_abort: false,
  };
  if (!fn || !fn.body) return out;

  function leafOfCall(n) {
    if (!ts.isCallExpression(n)) return "";
    return callLeaf(calleeName(n.expression));
  }

  function walkTimers(n) {
    if (!n) return;
    if (isFunctionLike(n) && n !== fn) return;
    if (ts.isCallExpression(n)) {
      const leaf = leafOfCall(n);
      if (leaf === "setTimeout") out.has_timeout = true;
      if (leaf === "setInterval") out.has_interval = true;
    }
    ts.forEachChild(n, walkTimers);
  }

  function walkCleanup(n) {
    if (!n) return;
    if (ts.isCallExpression(n)) {
      const leaf = leafOfCall(n);
      if (leaf === "clearTimeout" || leaf === "clearInterval") {
        out.has_cleanup_timer = true;
      }
      if (leaf === "abort") out.has_cleanup_abort = true;
    }
    ts.forEachChild(n, walkCleanup);
  }

  function considerCleanupExpr(expr) {
    if (!expr) return;
    const u = unwrap(expr);
    if (isFunctionLike(u) && u.body) walkCleanup(u.body);
  }

  function walkReturns(n) {
    if (!n) return;
    if (isFunctionLike(n) && n !== fn) return;
    if (ts.isReturnStatement(n)) {
      considerCleanupExpr(n.expression);
      return;
    }
    ts.forEachChild(n, walkReturns);
  }

  walkTimers(fn.body);
  walkReturns(fn.body);
  if (!ts.isBlock(fn.body)) considerCleanupExpr(fn.body);
  return out;
}

function factoryTagName(expr) {
  const node = unwrapDeep(expr);
  if (!node) return "";
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  if (ts.isIdentifier(node)) return node.text;
  return clip(node.getText());
}

function objectLiteralAttrNodes(obj) {
  const out = [];
  for (const p of obj.properties) {
    if (ts.isSpreadAssignment(p)) continue;
    if (ts.isShorthandPropertyAssignment(p) && ts.isIdentifier(p.name)) {
      out.push({ name: p.name.text, expr: p.name });
      continue;
    }
    if (ts.isPropertyAssignment(p)) {
      const name = propName(p);
      if (!name) continue;
      out.push({ name, expr: p.initializer });
    }
  }
  return out;
}

function extract(filePath, text, failHard = true) {
  const sf = ts.createSourceFile(
    filePath, text, ts.ScriptTarget.Latest, true, scriptKind(filePath),
  );
  const diags = sf.parseDiagnostics || [];
  const errors = diags.filter((d) => d.category === ts.DiagnosticCategory.Error);
  if (errors.length) {
    for (const d of errors) {
      const msg = ts.flattenDiagnosticMessageText(d.messageText, "\n");
      process.stderr.write(`${filePath}: ${msg}\n`);
    }
    if (failHard) process.exit(1);
    return null;
  }

  const calls = [];
  const catchClauses = [];
  const functions = [];
  const binaries = [];
  const imports = [];
  const jsx = [];
  const effects = [];

  /** @type {Map<string, object>[]} */
  const scopes = [new Map()];
  const funcStack = [];
  const region = [];

  function currentScope() {
    return scopes[scopes.length - 1];
  }

  function isNameLocal(name) {
    for (let i = scopes.length - 1; i >= 0; i--) {
      if (scopes[i].has(name)) return true;
    }
    return false;
  }

  function lookupInFunction(name) {
    const floor = funcStack.length ? funcStack[funcStack.length - 1].scopeIndex : 0;
    for (let i = scopes.length - 1; i >= floor; i--) {
      if (scopes[i].has(name)) return scopes[i].get(name);
    }
    return null;
  }

  function analyzeInit(expr) {
    if (!expr) return { hasSignal: false, unknown: true, origin: null };
    const node = unwrapDeep(expr);
    if (ts.isObjectLiteralExpression(node)) {
      let hasSignal = false;
      let unknown = false;
      for (const p of node.properties) {
        if (ts.isSpreadAssignment(p)) {
          const inner = analyzeInit(p.expression);
          if (inner.hasSignal) hasSignal = true;
          if (inner.unknown) unknown = true;
        } else if (propName(p) === "signal") {
          hasSignal = true;
        }
      }
      return { hasSignal, unknown: hasSignal ? false : unknown, origin: null };
    }
    if (ts.isIdentifier(node)) {
      const b = lookupInFunction(node.text);
      if (!b) return { hasSignal: false, unknown: true, origin: node.text };
      return {
        hasSignal: !!b.hasSignal,
        unknown: !!b.unknown && !b.hasSignal,
        origin: b.origin || node.text,
      };
    }
    if (ts.isNewExpression(node)) {
      const n = calleeName(node.expression);
      if (n === "Request" || n.endsWith(".Request")) {
        if (node.arguments && node.arguments.length >= 2) {
          return analyzeInit(node.arguments[1]);
        }
        return { hasSignal: false, unknown: true, origin: n };
      }
    }
    if (ts.isCallExpression(node)) {
      return {
        hasSignal: false,
        unknown: true,
        origin: calleeName(node.expression) || null,
      };
    }
    if (ts.isPropertyAccessExpression(node)) {
      return { hasSignal: false, unknown: true, origin: clip(node.getText()) };
    }
    return { hasSignal: false, unknown: true, origin: null };
  }

  function originOf(expr) {
    if (!expr) return null;
    const node = unwrapDeep(expr);
    if (ts.isIdentifier(node)) {
      const b = lookupInFunction(node.text);
      if (b && b.origin) return b.origin;
      return node.text;
    }
    if (ts.isCallExpression(node)) return calleeName(node.expression) || null;
    if (ts.isPropertyAccessExpression(node)) return clip(node.getText());
    if (ts.isNewExpression(node)) return calleeName(node) || null;
    return null;
  }

  function initializerIsGlobalRoot(init) {
    if (!init) return false;
    const node = unwrapDeep(init);
    return ts.isIdentifier(node) && GLOBAL_ROOTS.has(node.text);
  }

  function bindPattern(nameNode, info, initializer) {
    if (!nameNode) return;
    if (ts.isIdentifier(nameNode)) {
      currentScope().set(nameNode.text, {
        hasSignal: !!info.hasSignal,
        unknown: !!info.unknown && !info.hasSignal,
        origin: info.origin || nameNode.text,
      });
      return;
    }
    if (ts.isObjectBindingPattern(nameNode)) {
      for (const el of nameNode.elements) {
        if (!ts.isBindingElement(el)) continue;
        if (ts.isIdentifier(el.name) && el.name.text === "fetch"
            && initializerIsGlobalRoot(initializer)) {
          continue;
        }
        bindPattern(el.name, { hasSignal: false, unknown: true, origin: el.name.getText() }, null);
      }
      return;
    }
    if (ts.isArrayBindingPattern(nameNode)) {
      for (const el of nameNode.elements) {
        if (ts.isOmittedExpression(el)) continue;
        if (ts.isBindingElement(el)) {
          bindPattern(el.name, { hasSignal: false, unknown: true, origin: null }, null);
        }
      }
    }
  }

  function bindHoistedFunctions(container) {
    const stmts = ts.isSourceFile(container) || ts.isBlock(container) || ts.isModuleBlock(container)
      ? container.statements
      : null;
    if (!stmts) return;
    for (const stmt of stmts) {
      if (ts.isFunctionDeclaration(stmt) && stmt.name) {
        currentScope().set(stmt.name.text, {
          hasSignal: false, unknown: true, origin: stmt.name.text,
        });
      }
    }
  }

  function innermostHandler() {
    if (!funcStack.length) return { in_handler: false, param_names: [] };
    const top = funcStack[funcStack.length - 1];
    return { in_handler: top.is_handler, param_names: top.params };
  }

  function visitFunction(node) {
    if (!node.body) {
      ts.forEachChild(node, visit);
      return;
    }
    const params = paramNames(node);
    const is_handler = isHandlerParams(params) || isRouteCallback(node);
    const rec = {
      name: functionName(node),
      line_start: lineOf(sf, node.getStart(sf)),
      params,
      is_handler,
    };
    functions.push(rec);

    const scope = new Map();
    scopes.push(scope);
    funcStack.push({
      scopeIndex: scopes.length - 1,
      params,
      is_handler,
    });
    for (const p of node.parameters) {
      if (skipThisParam(p)) continue;
      bindPattern(p.name, { hasSignal: false, unknown: true, origin: null }, p.initializer || null);
    }
    visit(node.body);
    funcStack.pop();
    scopes.pop();
  }

  function recordCall(node) {
    const name = calleeName(node.expression);
    const args = [...(node.arguments || [])];
    const args_summary = args.map((a) => clip(a.getText(sf)));
    let has_signal_option = false;
    for (const a of args) {
      const u = unwrap(a);
      if (ts.isObjectLiteralExpression(u) && objectLiteralHasSignalProperty(u)) {
        has_signal_option = true;
      }
    }

    let resolved_signal = false;
    let options_unknown = false;
    if (args.length >= 2) {
      const an = analyzeInit(args[1]);
      if (an.hasSignal) resolved_signal = true;
      else if (an.unknown) options_unknown = true;
    } else if (args.length === 1) {
      const u = unwrap(args[0]);
      if (ts.isObjectLiteralExpression(u)) {
        const an = analyzeInit(u);
        if (an.hasSignal) resolved_signal = true;
        else if (an.unknown) options_unknown = true;
      } else if (looksLikeRequest(args[0])) {
        options_unknown = true;
      }
    }

    const first = args[0];
    const expr = unwrap(node.expression);
    const callee_is_local = ts.isIdentifier(expr) && expr.text === "fetch" && isNameLocal("fetch");
    const stringify = !!(first && (() => {
      const n = unwrapDeep(first);
      return ts.isCallExpression(n) && calleeName(n.expression) === "JSON.stringify";
    })());

    calls.push({
      name,
      line: lineOf(sf, node.getStart(sf)),
      args_summary,
      has_signal_option,
      in_try: region.length > 0 && region[region.length - 1] === "try",
      callee_is_local,
      resolved_signal,
      options_unknown,
      arg_count: args.length,
      wrapped_by: parentCallName(node),
      first_arg_kind: first ? firstArgKind(first) : null,
      first_arg_name: first ? firstArgName(first) : null,
      stringify_roundtrip: stringify,
      in_handler: innermostHandler().in_handler,
      arg_origins: args.map((a) => originOf(a)),
    });
  }

  function pushAttr(list, name, expr, is_expression, fn) {
    const classified = expr ? classifyExpr(expr) : { kind: "other", value_summary: "true" };
    list.push({
      name,
      kind: classified.kind,
      value_summary: classified.value_summary,
      is_expression,
      has_scheme_allowlist: !!(fn && expr && hasSchemeAllowlist(fn, expr)),
    });
  }

  function recordJsx(el) {
    const fn = enclosingFunction(el);
    const attrs = [];
    const props = el.attributes && el.attributes.properties ? el.attributes.properties : [];
    for (const attr of props) {
      if (ts.isJsxSpreadAttribute(attr)) continue;
      if (!ts.isJsxAttribute(attr)) continue;
      const name = jsxAttrName(attr);
      if (!attr.initializer) {
        attrs.push({
          name, kind: "other", value_summary: "true",
          is_expression: false, has_scheme_allowlist: false,
        });
        continue;
      }
      if (ts.isStringLiteral(attr.initializer)) {
        attrs.push({
          name, kind: "string_literal",
          value_summary: attr.initializer.text,
          is_expression: false, has_scheme_allowlist: false,
        });
        continue;
      }
      if (ts.isJsxExpression(attr.initializer)) {
        const expr = attr.initializer.expression;
        if (!expr) continue;
        pushAttr(attrs, name, expr, true, fn);
      }
    }
    jsx.push({
      tag: jsxTagName(el),
      line: lineOf(sf, el.getStart(sf)),
      attrs,
    });
  }

  function recordEffect(node) {
    const kindLeaf = callLeaf(calleeName(node.expression));
    if (kindLeaf !== "useEffect" && kindLeaf !== "useLayoutEffect") return;
    const first = node.arguments && node.arguments[0];
    const fn = first ? unwrapDeep(first) : null;
    const flags = (fn && isFunctionLike(fn))
      ? inspectEffectFn(fn)
      : {
        has_timeout: false, has_interval: false,
        has_cleanup_timer: false, has_cleanup_abort: false,
      };
    effects.push({
      line: lineOf(sf, node.getStart(sf)),
      kind: kindLeaf,
      has_timeout: flags.has_timeout,
      has_interval: flags.has_interval,
      has_cleanup_timer: flags.has_cleanup_timer,
      has_cleanup_abort: flags.has_cleanup_abort,
    });
  }

  function recordJsxFactory(node) {
    const leaf = callLeaf(calleeName(node.expression));
    if (!JSX_FACTORY_LEAF.has(leaf)) return;
    const args = node.arguments || [];
    if (!args.length) return;
    const props = args[1] ? unwrapDeep(args[1]) : null;
    if (!props || !ts.isObjectLiteralExpression(props)) return;
    const fn = enclosingFunction(node);
    const attrs = [];
    for (const { name, expr } of objectLiteralAttrNodes(props)) {
      pushAttr(attrs, name, expr, true, fn);
    }
    jsx.push({
      tag: factoryTagName(args[0]),
      line: lineOf(sf, node.getStart(sf)),
      attrs,
    });
  }

  function recordBinary(node) {
    const op = node.operatorToken.getText(sf);
    if (op !== "||" && op !== "??") return;
    let right = unwrap(node.right);
    let sign = "";
    if (ts.isPrefixUnaryExpression(right)
        && (right.operator === ts.SyntaxKind.MinusToken
            || right.operator === ts.SyntaxKind.PlusToken)
        && ts.isNumericLiteral(unwrap(right.operand))) {
      sign = right.operator === ts.SyntaxKind.MinusToken ? "-" : "";
      right = unwrap(right.operand);
    }
    let right_kind = "other";
    let right_value = null;
    if (ts.isNumericLiteral(right)) {
      right_kind = "number";
      right_value = sign + right.text;
    }
    const leftNode = unwrap(node.left);
    let left_kind = "other";
    let left_callee = null;
    if (ts.isIdentifier(leftNode)) {
      left_kind = "identifier";
    } else if (ts.isPropertyAccessExpression(leftNode)
        || ts.isElementAccessExpression(leftNode)) {
      left_kind = "property";
    } else if (ts.isCallExpression(leftNode) || ts.isNewExpression(leftNode)) {
      left_kind = "call";
      left_callee = calleeName(
        ts.isCallExpression(leftNode) ? leftNode.expression : leftNode.expression,
      ) || null;
    }
    binaries.push({
      op,
      line: lineOf(sf, node.getStart(sf)),
      right_kind,
      right_value,
      left_summary: clip(node.left.getText(sf)),
      left_kind,
      left_callee,
    });
  }

  function recordImport(node) {
    if (ts.isImportDeclaration(node)
        && node.moduleSpecifier
        && ts.isStringLiteral(node.moduleSpecifier)) {
      imports.push({
        source: node.moduleSpecifier.text,
        line: lineOf(sf, node.getStart(sf)),
        kind: "static",
        is_type_only: !!(node.importClause && node.importClause.isTypeOnly),
      });
      return;
    }
    if (ts.isExportDeclaration(node)
        && node.moduleSpecifier
        && ts.isStringLiteral(node.moduleSpecifier)) {
      imports.push({
        source: node.moduleSpecifier.text,
        line: lineOf(sf, node.getStart(sf)),
        kind: "static",
        is_type_only: !!node.isTypeOnly,
      });
    }
  }

  function visitCatch(node) {
    const { in_handler, param_names } = innermostHandler();
    const tryStmt = node.parent && ts.isTryStatement(node.parent) ? node.parent : null;
    catchClauses.push({
      line: lineOf(sf, node.getStart(sf)),
      body_empty: !node.block || node.block.statements.every((s) => ts.isEmptyStatement(s)),
      in_handler,
      param_names,
      try_has_call: !!(tryStmt && containsCall(tryStmt.tryBlock)),
    });
    scopes.push(new Map());
    if (node.variableDeclaration) {
      bindPattern(
        node.variableDeclaration.name,
        { hasSignal: false, unknown: true, origin: null },
        node.variableDeclaration.initializer || null,
      );
    }
    visit(node.block);
    scopes.pop();
  }

  function visit(node) {
    if (!node) return;
    if (isFunctionLike(node)) {
      visitFunction(node);
      return;
    }
    if (ts.isTryStatement(node)) {
      region.push("try");
      visit(node.tryBlock);
      region.pop();
      if (node.catchClause) {
        region.push("catch");
        visitCatch(node.catchClause);
        region.pop();
      }
      if (node.finallyBlock) {
        region.push("finally");
        visit(node.finallyBlock);
        region.pop();
      }
      return;
    }
    if (ts.isCatchClause(node)) {
      visitCatch(node);
      return;
    }
    if (ts.isBlock(node) || ts.isModuleBlock(node)) {
      scopes.push(new Map());
      bindHoistedFunctions(node);
      ts.forEachChild(node, visit);
      scopes.pop();
      return;
    }
    if (ts.isSourceFile(node)) {
      bindHoistedFunctions(node);
      ts.forEachChild(node, visit);
      return;
    }
    if (ts.isVariableDeclaration(node)) {
      bindPattern(node.name, { hasSignal: false, unknown: true, origin: null }, node.initializer || null);
      if (node.initializer) visit(node.initializer);
      bindPattern(node.name, analyzeInit(node.initializer), node.initializer || null);
      return;
    }
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      recordImport(node);
    }
    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      recordJsx(node);
    }
    if (ts.isCallExpression(node)) {
      recordCall(node);
      recordEffect(node);
      recordJsxFactory(node);
    }
    if (ts.isBinaryExpression(node)) {
      recordBinary(node);
    }
    ts.forEachChild(node, visit);
  }

  visit(sf);
  return {
    file: filePath, calls, catch_clauses: catchClauses, functions, binaries,
    imports, jsx, effects,
  };
}

async function stdioMain() {
  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const filePath = line.trim();
    if (!filePath) continue;
    try {
      const text = fs.readFileSync(filePath, "utf8");
      const facts = extract(filePath, text, false);
      process.stdout.write(JSON.stringify(facts) + "\n");
    } catch (err) {
      process.stderr.write(`read/extract failed: ${err.message}\n`);
      process.stdout.write("null\n");
    }
  }
}

function main(argv) {
  if (argv[2] === "--stdio") {
    stdioMain();
    return;
  }
  if (argv.length < 3) {
    process.stderr.write("usage: node facts.mjs <file.ts>\n");
    process.exit(2);
  }
  const filePath = argv[2];
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    process.stderr.write(`read failed: ${err.message}\n`);
    process.exit(1);
  }
  const facts = extract(filePath, text);
  process.stdout.write(JSON.stringify(facts) + "\n");
}

main(process.argv);
