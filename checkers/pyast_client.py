"""In-process Python AST facts extractor (stdlib ast only).

Detectors consume these facts instead of regexing source. Parse failures
return None (FP-biased silence). No subprocess, no extra deps.
"""
from __future__ import annotations

import ast
from typing import Any


def load_facts(source: str, filename: str = "<inline>") -> dict | None:
    """Parse `source` and return a facts dict, or None on SyntaxError."""
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError):
        return None
    visitor = _FactsVisitor(filename)
    visitor.visit(tree)
    return visitor.result()


def _unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name for a Call func / Attribute / Name."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return _unparse(node)


def _resolve(name: str, aliases: dict[str, str]) -> str:
    """Rewrite the leftmost identifier through the import alias map."""
    if not name:
        return name
    head, _, rest = name.partition(".")
    mapped = aliases.get(head, head)
    return f"{mapped}.{rest}" if rest else mapped


def _handler_type(node: ast.ExceptHandler) -> str | None:
    if node.type is None:
        return None
    if isinstance(node.type, ast.Tuple):
        parts = []
        for elt in node.type.elts:
            parts.append(_dotted(elt) or _unparse(elt))
        return " | ".join(parts) if parts else None
    return _dotted(node.type) or _unparse(node.type)


def _body_kind(body: list[ast.stmt]) -> str:
    if len(body) != 1:
        return "other"
    stmt = body[0]
    if isinstance(stmt, ast.Pass):
        return "pass"
    if isinstance(stmt, ast.Expr):
        val = stmt.value
        if isinstance(val, ast.Constant) and val.value is Ellipsis:
            return "ellipsis"
        if isinstance(val, ast.Name) and val.id == "Ellipsis":
            return "ellipsis"
    return "other"


def _is_static_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


def _is_static_str_expr(node: ast.AST) -> bool:
    """True when `node` is a compile-time string (no name/call fragments)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                continue
            if isinstance(part, ast.FormattedValue):
                val = part.value
                if _is_static_constant(val) or _is_static_str_expr(val):
                    continue
                return False
            return False
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_static_str_expr(node.left) and _is_static_str_expr(node.right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        if not _is_static_str_expr(node.func.value):
            return False
        if any(isinstance(a, ast.Starred) for a in node.args):
            return False
        if any(kw.arg is None for kw in node.keywords):
            return False
        for arg in node.args:
            if not (_is_static_str_expr(arg) or _is_static_constant(arg)):
                return False
        for kw in node.keywords:
            if not (_is_static_str_expr(kw.value) or _is_static_constant(kw.value)):
                return False
        return True
    return False


def _first_arg_kind(arg: ast.AST) -> str:
    """Classify a call's first positional argument.

    Values: string_literal / fstring / concat / format / name / other.
    All-literal f-strings, concatenations, and .format() collapse to
    string_literal (FP-biased: 100% literal SQL is silent).
    """
    if _is_static_str_expr(arg):
        return "string_literal"
    if isinstance(arg, ast.JoinedStr):
        return "fstring"
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        return "concat"
    if (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "format"
    ):
        return "format"
    if isinstance(arg, ast.Name):
        return "name"
    return "other"


def _call_record(node: ast.Call, aliases: dict[str, str]) -> dict[str, Any]:
    raw = _dotted(node.func)
    name = _resolve(raw, aliases)
    keywords = [kw.arg for kw in node.keywords if kw.arg]
    keyword_values = {
        kw.arg: _unparse(kw.value)
        for kw in node.keywords
        if kw.arg is not None
    }
    args_summary = [_unparse(a)[:80] for a in node.args]
    has_starargs = any(isinstance(a, ast.Starred) for a in node.args)
    has_kwargs = any(kw.arg is None for kw in node.keywords)
    first = node.args[0] if node.args else None
    return {
        "name": name,
        "line": getattr(node, "lineno", 1) or 1,
        "keywords": keywords,
        "args_summary": args_summary,
        "keyword_values": keyword_values,
        "has_starargs": has_starargs,
        "has_kwargs": has_kwargs,
        "first_arg_kind": _first_arg_kind(first) if first is not None else None,
        "first_arg_summary": _unparse(first)[:80] if first is not None else None,
    }


class _FactsVisitor(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.functions: list[dict[str, Any]] = []
        self.except_handlers: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self._alias_stack: list[dict[str, str]] = [{}]
        self._fn_stack: list[dict[str, Any]] = []
        self._parent_stack: list[ast.AST] = []
        self._region: list[str] = []

    def result(self) -> dict[str, Any]:
        return {
            "file": self.filename,
            "functions": self.functions,
            "except_handlers": self.except_handlers,
            "calls": self.calls,
        }

    @property
    def _aliases(self) -> dict[str, str]:
        return self._alias_stack[-1]

    def _push_scope(self) -> None:
        self._alias_stack.append(dict(self._aliases))

    def _pop_scope(self) -> None:
        if len(self._alias_stack) > 1:
            self._alias_stack.pop()

    def _in_try(self) -> bool:
        return bool(self._region) and self._region[-1] == "try"

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self._parent_stack.append(node)
            try:
                self.visit(child)
            finally:
                self._parent_stack.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            # import httpx as hx -> hx=httpx; import urllib.request -> urllib=urllib
            bound = alias.asname or alias.name.split(".")[0]
            self._aliases[bound] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            self.generic_visit(node)
            return
        mod = node.module
        for alias in node.names:
            if alias.name == "*":
                continue
            bound = alias.asname or alias.name
            self._aliases[bound] = f"{mod}.{alias.name}"
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
        record = {
            "name": node.name,
            "async": is_async,
            "line_start": node.lineno,
            "line_end": getattr(node, "end_lineno", node.lineno) or node.lineno,
            "decorators": [_unparse(d) for d in node.decorator_list],
            "calls": [],
        }
        self.functions.append(record)
        self._fn_stack.append(record)
        self._push_scope()
        for dec in node.decorator_list:
            self.visit(dec)
        for arg in node.args.args:
            if arg.annotation is not None:
                self.visit(arg.annotation)
        if node.returns is not None:
            self.visit(node.returns)
        for stmt in node.body:
            self.visit(stmt)
        self._pop_scope()
        self._fn_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, True)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._push_scope()
        self.generic_visit(node)
        self._pop_scope()

    def _emit_call(self, rec: dict[str, Any]) -> None:
        rec["in_try"] = self._in_try()
        self.calls.append(rec)
        if self._fn_stack:
            self._fn_stack[-1]["calls"].append(rec)

    def visit_Call(self, node: ast.Call) -> None:
        rec = _call_record(node, self._aliases)
        self._emit_call(rec)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Flask `request.json` is a property (Load), not a Call. Record it
        # with the same call-shaped facts so detectors can see it. Skip the
        # Attribute that is the func of `request.json()`.
        parent = self._parent_stack[-1] if self._parent_stack else None
        is_call_func = isinstance(parent, ast.Call) and parent.func is node
        if (
            not is_call_func
            and isinstance(node.ctx, ast.Load)
            and node.attr == "json"
        ):
            raw = _dotted(node)
            name = _resolve(raw, self._aliases)
            recv = name.rsplit(".", 1)[0] if "." in name else ""
            recv_leaf = recv.rsplit(".", 1)[-1] if recv else ""
            if recv_leaf in {"request", "Request"}:
                self._emit_call({
                    "name": name,
                    "line": getattr(node, "lineno", 1) or 1,
                    "keywords": [],
                    "args_summary": [],
                    "keyword_values": {},
                    "has_starargs": False,
                    "has_kwargs": False,
                    "first_arg_kind": None,
                    "first_arg_summary": None,
                })
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        in_fn = self._fn_stack[-1]["name"] if self._fn_stack else None
        for handler in node.handlers:
            self.except_handlers.append({
                "line": handler.lineno,
                "type": _handler_type(handler),
                "body_kind": _body_kind(handler.body),
                "in_function": in_fn,
            })
        self._region.append("try")
        for stmt in node.body:
            self.visit(stmt)
        self._region.pop()
        for handler in node.handlers:
            self._region.append("except")
            self.visit(handler)
            self._region.pop()
        self._region.append("else")
        for stmt in node.orelse:
            self.visit(stmt)
        self._region.pop()
        self._region.append("finally")
        for stmt in node.finalbody:
            self.visit(stmt)
        self._region.pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Lambdas are not functions in the facts schema; still collect calls.
        self.generic_visit(node)
