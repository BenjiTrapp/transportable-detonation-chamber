"""SPL-like search over in-memory log events (the LOGS tab).

A small subset of Splunk's search language: free words, phrases, field
comparisons, ``AND``/``OR``/``NOT`` with parentheses, ``earliest=``/``latest=``
and the pipes head, tail, sort, dedup, table, fields, stats, top, rare and
timechart. There is no user regex anywhere: words and values are plain text and
``*`` is the only wildcard (matched by a linear scan, not a regex), so a search
can neither fail on odd characters nor run away on a crafted pattern.

An event is ``{"id", "time", "source", "message", "fields": {...}}``. A field
name is looked up in ``id``/``time``/``source``/``message`` first and then in
``fields``; ``sourcetype`` and ``index`` are aliases for ``source`` (and
``_time``/``_raw`` for ``time``/``message``; for a ``powershell`` event ``script``
too, unless it has a field of that name). A field that is absent or
``None`` counts as missing.

The query is parsed once into an AST (``parse``) and compiled into predicate
closures, so one search over 50 000 events does no per-event parsing or
compilation, only the read of each event's own timestamp.

``run`` returns one dict for the UI::

    {type: "events"|"table"|"timechart", events, columns, rows, count, matched,
     truncated, histogram: {bins: [{start, end, counts: {source: n}}], span_s},
     fields: [{name, count, top: [{value, count}]}]}

``matched`` and ``histogram`` describe the events that matched the search
part; ``count`` is the number of events or rows after the pipes.
"""

from __future__ import annotations

import math
import operator
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Tuple

MAX_QUERY_LEN = 4000
MAX_VALUES = 100
MAX_TIMECHART_BINS = 1000
MAX_NESTING = 50
MAX_TIMECHART_SERIES = 10
HISTOGRAM_BINS = 60
SIDEBAR_VALUES = 10
SIDEBAR_FIELDS = 200
SIDEBAR_VALUE_LEN = 200

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_NICE_SPANS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200,
               86400, 172800, 604800, 2592000]
_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()
_SEP = "\x00"
# Times outside 1970-01-01..9999-12-31 are rejected: strftime/gmtime cannot show them everywhere.
_MAX_EPOCH = 253402300800
_PARSE_ANCHOR = 2000000000.0

_ISO = re.compile(
    r"^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,](\d+))?)?)?\s*(Z|[+-]\d\d(?::?\d\d)?)?$")
_REL = re.compile(r"^([+-])(\d{1,9})([smhdw])$")
_NUMBER = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_SPAN = re.compile(r"^(\d{1,9})([smhd])$")
_DIGITS = re.compile(r"^\d+$")

_TOP_LEVEL = {"id": "id", "time": "time", "source": "source", "message": "message",
              "sourcetype": "source", "index": "source", "_time": "time", "_raw": "message"}


class SearchError(Exception):
    """A search that cannot be parsed or run; ``pos`` is the offending index in the query."""

    def __init__(self, message: str, pos: int = 0):
        super().__init__(message)
        self.pos = pos


# ---- time ------------------------------------------------------------------------------------


def _parse_iso(value: str) -> Optional[float]:
    """Epoch seconds of an ISO-8601 time (naive means UTC), or None."""
    m = _ISO.match(value)
    if not m:
        return None
    year, month, day, hour, minute, sec, frac, zone = m.groups()
    try:
        ordinal = date(int(year), int(month), int(day)).toordinal()
        h, mi, s = int(hour or 0), int(minute or 0), int(sec or 0)
        if h > 23 or mi > 59 or s > 60:
            return None
        epoch = (ordinal - _EPOCH_ORDINAL) * 86400 + h * 3600 + mi * 60 + s
        if frac:
            epoch += float("0." + frac)
        if zone and zone != "Z":
            digits = zone[1:].replace(":", "")
            offset = int(digits[:2]) * 3600 + int(digits[2:] or 0) * 60
            epoch -= offset if zone[0] == "+" else -offset
    except (ValueError, OverflowError):
        return None
    return float(epoch) if 0 <= epoch < _MAX_EPOCH else None


def _iso(epoch: float) -> str:
    """ISO-8601 UTC text, clamped to 1970..9999 (no gmtime: it fails on negative values on Windows)."""
    epoch = min(max(epoch, 0.0), _MAX_EPOCH - 1.0)
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=int(epoch))).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_epoch(value: str, now_epoch: float) -> Optional[float]:
    """Epoch seconds of ``now``, a relative time (-15m) or an ISO-8601 time; None when invalid."""
    if value == "now":
        epoch: Optional[float] = now_epoch
    else:
        m = _REL.match(value)
        if m:
            delta = int(m.group(2)) * _UNITS[m.group(3)]
            epoch = now_epoch - delta if m.group(1) == "-" else now_epoch + delta
        else:
            epoch = _parse_iso(value)
    return epoch if epoch is not None and 0 <= epoch < _MAX_EPOCH else None


def _now_epoch(now: datetime) -> float:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.timestamp()


def resolve_time(value: str, now: datetime) -> datetime:
    """``-15m``/``-2h``/``-1d``/``-1w``/``now``/ISO-8601 as an aware UTC datetime."""
    epoch = _to_epoch(value, _now_epoch(now)) if isinstance(value, str) else None
    if epoch is None:
        raise SearchError(f"Invalid time: {value}")
    try:
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=epoch)
    except OverflowError:
        raise SearchError(f"Invalid time: {value}") from None


def _event_epoch(ev: Dict[str, Any]) -> Optional[float]:
    t = ev.get("time")
    return _parse_iso(t) if isinstance(t, str) else None


# ---- values ----------------------------------------------------------------------------------


def _items(v: Any) -> List[Any]:
    """The scalar values of a field: a list is flattened, None is dropped."""
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        out: List[Any] = []
        for x in v:
            out.extend(_items(x))
        return out
    return [v]


def _text(v: Any) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, str):
        if not _NUMBER.match(v.strip()):
            return None
    elif not isinstance(v, (int, float)):
        return None
    try:
        f = float(v)
    except (ValueError, OverflowError):
        return None
    return f if math.isfinite(f) else None


def _clean(x: float) -> Any:
    """A number for a result cell; None when it is not finite (JSON has no inf/nan)."""
    if not math.isfinite(x):
        return None
    if x == int(x) and abs(x) < 1e15:
        return int(x)
    return round(x, 6)


def _finite(v: Any) -> Any:
    """A result cell without inf/nan (JSON cannot carry them); lists are checked item by item."""
    if isinstance(v, float):
        return v if math.isfinite(v) else None
    if isinstance(v, (list, tuple)):
        return [_finite(x) for x in v]
    return v


def _scalar(v: Any) -> Any:
    """A table cell for grouping: a list becomes one text."""
    if isinstance(v, (list, tuple)):
        return ", ".join(_text(x) for x in _items(v))
    return v


def _sort_key(v: Any) -> Tuple[int, float, str]:
    v = _scalar(v)
    n = _num(v)
    if n is not None:
        return (0, n, "")
    return (1, 0.0, _text(v).lower())


def _event_getter(name: str) -> Callable[[Dict[str, Any]], Any]:
    top = _TOP_LEVEL.get(name)
    if top:
        return lambda ev: ev.get(top)

    def get(ev):
        fields = ev.get("fields")
        value = fields.get(name) if isinstance(fields, dict) else None
        if value is None and name == "script" and ev.get("source") == "powershell":
            return ev.get("message")        # a script block is stored once, as the message
        return value
    return get


def _row_getter(name: str) -> Callable[[Dict[str, Any]], Any]:
    return lambda row: row.get(name)


def _haystack(ev: Dict[str, Any]) -> str:
    """Lower-cased message and all field values, joined by a NUL no search can contain."""
    parts = []
    msg = ev.get("message")
    if msg is not None:
        parts.append(_text(msg))
    fields = ev.get("fields")
    if isinstance(fields, dict):
        for v in fields.values():
            for x in _items(v):
                parts.append(_text(x))
    return _SEP.join(parts).lower()


def _glob_in(parts: List[str], text: str) -> bool:
    """Whether the literal ``parts`` (a lower-cased word split at ``*``) occur in order inside ``text``."""
    pos = 0
    for p in parts:
        if p:
            i = text.find(p, pos)
            if i < 0:
                return False
            pos = i + len(p)
    return True


def _glob_full(parts: List[str], text: str) -> bool:
    """Whether ``text`` as a whole matches the lower-cased value split at ``*`` (at least one ``*``)."""
    first, last = parts[0], parts[-1]
    end = len(text) - len(last)
    if not text.startswith(first) or end < len(first) or not text.endswith(last):
        return False
    pos = len(first)
    for p in parts[1:-1]:
        if p:
            i = text.find(p, pos, end)
            if i < 0:
                return False
            pos = i + len(p)
    return True


# ---- tokenizer -------------------------------------------------------------------------------


class Token(NamedTuple):
    kind: str  # word, str, lp, rp, pipe, comma, op, eof
    value: str
    pos: int


_WORD_STOP = set('(),|"=<>')


def _tokenize(text: str) -> List[Token]:
    toks: List[Token] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == '"':
            j, buf = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n and text[j + 1] == '"':
                    buf.append('"')
                    j += 2
                else:
                    buf.append(text[j])
                    j += 1
            if j >= n:
                raise SearchError("Unterminated string", i)
            toks.append(Token("str", "".join(buf), i))
            i = j + 1
        elif c == "(":
            toks.append(Token("lp", c, i))
            i += 1
        elif c == ")":
            toks.append(Token("rp", c, i))
            i += 1
        elif c == "|":
            toks.append(Token("pipe", c, i))
            i += 1
        elif c == ",":
            toks.append(Token("comma", c, i))
            i += 1
        elif c in "=<>!" and (c != "!" or text.startswith("!=", i)):
            two = text[i:i + 2]
            op = two if two in ("!=", ">=", "<=") else c
            toks.append(Token("op", op, i))
            i += len(op)
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in _WORD_STOP and not text.startswith("!=", j):
                j += 1
            toks.append(Token("word", text[i:j], i))
            i = j
    toks.append(Token("eof", "", n))
    return toks


# ---- AST and parser --------------------------------------------------------------------------
#
# Search nodes are tuples:
#   ("true",)  ("and", [nodes])  ("or", [nodes])  ("not", node)
#   ("text", word, pos)  ("cmp", field, op, value, pos)


@dataclass
class Pipe:
    name: str
    args: Dict[str, Any]
    pos: int


@dataclass
class Query:
    terms: Optional[tuple]
    pipes: List[Pipe] = field(default_factory=list)
    earliest: Optional[str] = None
    latest: Optional[str] = None


_STATS_FUNCS = ("count", "dc", "sum", "avg", "min", "max", "values")
_COMMANDS = ("head", "tail", "sort", "dedup", "table", "fields", "stats", "top", "rare", "timechart")


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.toks = _tokenize(text)
        self.i = 0
        self.depth = 0
        self.earliest: Optional[str] = None
        self.latest: Optional[str] = None

    # token helpers
    def peek(self) -> Token:
        return self.toks[self.i]

    def next(self) -> Token:
        t = self.toks[self.i]
        if t.kind != "eof":
            self.i += 1
        return t

    def is_kw(self, t: Token, kw: str) -> bool:
        return t.kind == "word" and t.value == kw

    def skip_commas(self) -> None:
        while self.peek().kind == "comma":
            self.next()

    def unexpected(self, t: Token) -> SearchError:
        if t.kind == "eof":
            return SearchError("Unexpected end of query", t.pos)
        return SearchError(f"Unexpected {t.value}", t.pos)

    # search part
    def parse(self) -> Query:
        terms = None
        if self.peek().kind not in ("pipe", "eof"):
            terms = self.or_expr()
            t = self.peek()
            if t.kind == "rp":
                raise SearchError("Unbalanced parenthesis", t.pos)
            if t.kind not in ("pipe", "eof"):
                raise self.unexpected(t)
        pipes = []
        while self.peek().kind == "pipe":
            self.next()
            pipes.append(self.pipe())
        return Query(terms, pipes, self.earliest, self.latest)

    def or_expr(self, ctx: str = "") -> tuple:
        nodes = [self.and_expr(ctx)]
        while self.is_kw(self.peek(), "OR"):
            self.next()
            nodes.append(self.and_expr("OR"))
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    def and_expr(self, ctx: str) -> tuple:
        nodes = [self.not_expr(ctx)]
        while True:
            self.skip_commas()
            t = self.peek()
            if t.kind in ("eof", "pipe", "rp") or self.is_kw(t, "OR"):
                break
            if self.is_kw(t, "AND"):
                self.next()
                nodes.append(self.not_expr("AND"))
            else:
                nodes.append(self.not_expr(""))
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def enter(self, t: Token) -> None:
        """Count one level of nesting (parenthesis or NOT); the AST and its compiler recurse as deep."""
        self.depth += 1
        if self.depth > MAX_NESTING:
            raise SearchError("Query too nested", t.pos)

    def not_expr(self, ctx: str) -> tuple:
        t = self.peek()
        if self.is_kw(t, "NOT"):
            self.enter(t)
            self.next()
            node = ("not", self.not_expr("NOT"))
            self.depth -= 1
            return node
        return self.primary(ctx)

    def primary(self, ctx: str) -> tuple:
        self.skip_commas()
        t = self.peek()
        if t.kind == "lp":
            self.enter(t)
            self.next()
            if self.peek().kind == "rp":
                raise SearchError("Expected a search term", self.peek().pos)
            node = self.or_expr("(")
            if self.peek().kind != "rp":
                raise SearchError("Unbalanced parenthesis", t.pos)
            self.next()
            self.depth -= 1
            return node
        if t.kind in ("word", "str"):
            return self.term()
        if t.kind in ("eof", "pipe", "rp", "comma") or self.is_kw(t, "OR"):
            raise SearchError(f"Expected a search term after {ctx}" if ctx else "Expected a search term", t.pos)
        raise self.unexpected(t)

    def term(self) -> tuple:
        t = self.next()
        if self.peek().kind != "op":
            return ("text", t.value, t.pos)
        op = self.next()
        v = self.peek()
        if v.kind not in ("word", "str"):
            raise SearchError(f"Expected a value after {op.value}", v.pos)
        self.next()
        if t.kind == "word" and t.value in ("earliest", "latest"):
            if op.value != "=":
                raise SearchError(f"Expected = after {t.value}", op.pos)
            if _to_epoch(v.value, _PARSE_ANCHOR) is None:
                raise SearchError(f"Invalid time: {v.value}", v.pos)
            if t.value == "earliest":
                self.earliest = v.value
            else:
                self.latest = v.value
            return ("true",)
        return ("cmp", t.value, op.value, v.value, t.pos)

    # pipes
    def end_of_command(self) -> None:
        t = self.peek()
        if t.kind not in ("pipe", "eof"):
            raise self.unexpected(t)

    def pipe(self) -> Pipe:
        t = self.peek()
        if t.kind != "word":
            raise SearchError("Expected a command after |", t.pos)
        self.next()
        name = t.value.lower()
        if name not in _COMMANDS:
            raise SearchError(f"Unknown command: {t.value}", t.pos)
        args = getattr(self, "cmd_" + name)(name)
        self.end_of_command()
        return Pipe(name, args, t.pos)

    def count_arg(self, name: str, default: int, strict: bool = True) -> int:
        t = self.peek()
        if t.kind == "word" and _DIGITS.match(t.value):
            self.next()
            return int(t.value)
        if t.kind in ("eof", "pipe") or not strict:
            return default
        raise SearchError(f"Expected a number after {name}", t.pos)

    def field_list(self, name: str, signed: bool = False) -> List[Any]:
        out: List[Any] = []
        while True:
            self.skip_commas()
            t = self.peek()
            if t.kind not in ("word", "str"):
                break
            self.next()
            if signed and t.kind == "word" and t.value[:1] in "+-" and len(t.value) > 1:
                out.append((t.value[1:], t.value[0] == "-"))
            elif signed:
                out.append((t.value, False))
            else:
                out.append(t.value)
        if not out:
            raise SearchError(f"Expected a field name after {name}", self.peek().pos)
        return out

    def cmd_head(self, name: str) -> Dict[str, Any]:
        return {"n": self.count_arg(name, 10)}

    cmd_tail = cmd_head

    def cmd_sort(self, name: str) -> Dict[str, Any]:
        return {"keys": self.field_list(name, signed=True)}

    def cmd_dedup(self, name: str) -> Dict[str, Any]:
        return {"fields": self.field_list(name)}

    def cmd_table(self, name: str) -> Dict[str, Any]:
        return {"fields": self.field_list(name)}

    cmd_fields = cmd_table

    def cmd_top(self, name: str) -> Dict[str, Any]:
        n = self.count_arg(name, 10, strict=False)
        self.skip_commas()
        t = self.peek()
        if t.kind not in ("word", "str"):
            raise SearchError(f"Expected a field name after {name}", t.pos)
        self.next()
        return {"n": n, "field": t.value}

    cmd_rare = cmd_top

    def by_list(self) -> List[str]:
        t = self.peek()
        if t.kind == "word" and t.value.lower() == "by":
            self.next()
            return self.field_list("by")
        return []

    def cmd_stats(self, name: str) -> Dict[str, Any]:
        aggs = []
        while True:
            self.skip_commas()
            t = self.peek()
            if t.kind != "word" or t.value.lower() == "by":
                break
            self.next()
            func = t.value.lower()
            if func not in _STATS_FUNCS:
                raise SearchError(f"Unknown function: {t.value}", t.pos)
            arg = None
            if self.peek().kind == "lp":
                lp = self.next()
                a = self.peek()
                if a.kind in ("word", "str"):
                    self.next()
                    arg = a.value
                elif func != "count" or a.kind != "rp":
                    raise SearchError(f"Expected a field name in {func}()", a.pos)
                if self.peek().kind != "rp":
                    raise SearchError("Unbalanced parenthesis", lp.pos)
                self.next()
            elif func != "count":
                raise SearchError(f"Function {func} needs a field: {func}(field)", self.peek().pos)
            label = f"{func}({arg})" if arg is not None else func
            nt = self.peek()
            if nt.kind == "word" and nt.value.lower() == "as":
                self.next()
                a = self.peek()
                if a.kind not in ("word", "str"):
                    raise SearchError("Expected a name after as", a.pos)
                self.next()
                label = a.value
            aggs.append((func, arg, label))
        if not aggs:
            raise SearchError("Expected a function after stats", self.peek().pos)
        return {"aggs": aggs, "by": self.by_list()}

    def cmd_timechart(self, name: str) -> Dict[str, Any]:
        span = None
        t = self.peek()
        if t.kind == "word" and t.value.lower() == "span":
            self.next()
            if self.peek().kind != "op" or self.peek().value != "=":
                raise SearchError("Expected = after span", self.peek().pos)
            self.next()
            v = self.peek()
            m = _SPAN.match(v.value) if v.kind == "word" else None
            if not m or int(m.group(1)) == 0:
                raise SearchError(f"Invalid span: {v.value}", v.pos)
            self.next()
            span = int(m.group(1)) * _UNITS[m.group(2)]
        t = self.peek()
        if not (t.kind == "word" and t.value.lower() == "count"):
            raise SearchError("Expected count after timechart", t.pos)
        self.next()
        return {"span": span, "by": self.by_list()[:1]}


def parse(query: str) -> Query:
    if len(query) > MAX_QUERY_LEN:
        raise SearchError("Query too long", MAX_QUERY_LEN)
    return _Parser(query).parse()


# ---- compiling the search part ---------------------------------------------------------------

_Pred = Callable[[Dict[str, Any], List[Optional[str]]], bool]
_RELATIONAL = {">": operator.gt, "<": operator.lt, ">=": operator.ge, "<=": operator.le}


def _compile_text(word: str) -> _Pred:
    needle = word.lower()
    if needle.strip("*") == "":
        return lambda ev, box: True
    if "*" not in needle:
        def contains(ev, box):
            h = box[0]
            if h is None:
                h = box[0] = _haystack(ev)
            return needle in h
        return contains
    parts = needle.split("*")

    def matches(ev, box):
        h = box[0]
        if h is None:
            h = box[0] = _haystack(ev)
        for segment in h.split(_SEP):
            if _glob_in(parts, segment):
                return True
        return False
    return matches


def _compile_cmp(name: str, op: str, value: str) -> _Pred:
    get = _event_getter(name)
    if op in ("=", "!="):
        vl = value.lower()
        vnum = _num(value)
        if "*" in vl:
            parts = vl.split("*")

            def one(item):
                return _glob_full(parts, _text(item).lower())
        else:
            def one(item):
                if _text(item).lower() == vl:
                    return True
                return vnum is not None and _num(item) == vnum
    else:
        cmp = _RELATIONAL[op]
        vnum = _num(value)
        vl = value.lower()

        def one(item):
            n = _num(item) if vnum is not None else None
            if n is not None:
                return cmp(n, vnum)
            return cmp(_text(item).lower(), vl)

    if op == "!=":
        def pred(ev, box):
            v = get(ev)
            if v is None:
                return True
            if isinstance(v, (list, tuple)):
                return not any(one(x) for x in _items(v))
            return not one(v)
    else:
        def pred(ev, box):
            v = get(ev)
            if v is None:
                return False
            if isinstance(v, (list, tuple)):
                return any(one(x) for x in _items(v))
            return one(v)
    return pred


def _compile(node: tuple) -> _Pred:
    kind = node[0]
    if kind == "true":
        return lambda ev, box: True
    if kind == "text":
        return _compile_text(node[1])
    if kind == "cmp":
        return _compile_cmp(node[1], node[2], node[3])
    if kind == "not":
        inner = _compile(node[1])
        return lambda ev, box: not inner(ev, box)
    parts = [_compile(n) for n in node[1]]
    if kind == "and":
        def and_(ev, box):
            for p in parts:
                if not p(ev, box):
                    return False
            return True
        return and_

    def or_(ev, box):
        for p in parts:
            if p(ev, box):
                return True
        return False
    return or_


# ---- pipes -----------------------------------------------------------------------------------


class _State:
    """The working set between pipes: events first, rows (dicts) after a transforming pipe."""

    def __init__(self, items: List[Dict[str, Any]], rng: Optional[Tuple[float, float]]):
        self.items = items
        self.rows = False
        self.columns: Optional[List[str]] = None
        self.kind = "events"
        self.range = rng

    def getter(self, name: str) -> Callable[[Dict[str, Any]], Any]:
        return _row_getter(name) if self.rows else _event_getter(name)

    def set_rows(self, columns: List[str], rows: List[Dict[str, Any]], kind: str) -> None:
        self.items, self.columns, self.rows, self.kind = rows, columns, True, kind

    def item_epoch(self, item: Dict[str, Any]) -> Optional[float]:
        if not self.rows:
            return _event_epoch(item)
        t = item.get("_time") or item.get("time")
        return _parse_iso(t) if isinstance(t, str) else None


def _sort_items(state: _State, keys: List[Tuple[str, bool]]) -> None:
    items = state.items
    for name, desc in reversed(keys):
        get = state.getter(name)
        present, missing = [], []
        for item in items:
            (missing if get(item) is None else present).append(item)
        present.sort(key=lambda it: _sort_key(get(it)), reverse=desc)
        items = present + missing
    state.items = items


def _dedup(state: _State, names: List[str]) -> None:
    getters = [state.getter(n) for n in names]
    seen = set()
    out = []
    for item in state.items:
        key = []
        for g in getters:
            v = g(item)
            if v is None:
                break
            key.append(_text(_scalar(v)))
        else:
            k = tuple(key)
            if k not in seen:
                seen.add(k)
                out.append(item)
    state.items = out


def _table(state: _State, names: List[str]) -> None:
    getters = [state.getter(n) for n in names]
    rows = [{n: g(item) for n, g in zip(names, getters)} for item in state.items]
    state.set_rows(list(names), rows, "table")


def _aggregate(func: str, arg: Optional[str], items: List[Dict[str, Any]], get) -> Any:
    if func == "count":
        if arg is None:
            return len(items)
        return sum(1 for it in items if get(it) is not None)
    values: List[Any] = []
    for it in items:
        values.extend(_items(get(it)))
    if func == "dc":
        return len({_text(v) for v in values})
    if func == "values":
        return sorted({_text(v) for v in values}, key=lambda s: (s.lower(), s))[:MAX_VALUES]
    nums = [n for n in (_num(v) for v in values) if n is not None]
    if func == "sum":
        return _clean(sum(nums)) if nums else None
    if func == "avg":
        return _clean(round(sum(nums) / len(nums), 4)) if nums else None
    if not values:
        return None
    if len(nums) == len(values):
        return _clean(min(nums) if func == "min" else max(nums))
    pick = min if func == "min" else max
    return pick(values, key=lambda v: _text(v).lower())


def _stats(state: _State, aggs: List[Tuple[str, Optional[str], str]], by: List[str]) -> None:
    getters = {a[1]: state.getter(a[1]) for a in aggs if a[1] is not None}
    by_get = [state.getter(b) for b in by]
    groups: Dict[Tuple[str, ...], Tuple[List[Any], List[Dict[str, Any]]]] = {}
    for item in state.items:
        raw = []
        for g in by_get:
            v = g(item)
            if v is None:
                break
            raw.append(_scalar(v))
        else:
            key = tuple(_text(v) for v in raw)
            entry = groups.get(key)
            if entry is None:
                entry = groups[key] = (raw, [])
            entry[1].append(item)
    if not by and not groups:
        groups[()] = ([], [])
    columns = list(by) + [a[2] for a in aggs]
    rows = []
    for raw, items in sorted(groups.values(), key=lambda e: [_sort_key(v) for v in e[0]]):
        row = dict(zip(by, raw))
        for func, arg, label in aggs:
            row[label] = _aggregate(func, arg, items, getters.get(arg))
        rows.append(row)
    state.set_rows(columns, rows, "table")


def _top(state: _State, n: int, field_name: str, rare: bool) -> None:
    get = state.getter(field_name)
    counts: Counter = Counter()
    for item in state.items:
        for v in _items(get(item)):
            counts[_text(v)] += 1
    total = sum(counts.values())
    ordered = sorted(counts.items(), key=lambda kv: (kv[1] if rare else -kv[1], kv[0]))
    if n:
        ordered = ordered[:n]
    rows = [{field_name: v, "count": c, "percent": round(100.0 * c / total, 2)} for v, c in ordered]
    state.set_rows([field_name, "count", "percent"], rows, "table")


def _nice_span(raw: float) -> int:
    for s in _NICE_SPANS:
        if s >= raw:
            return s
    return int(math.ceil(raw / 86400.0)) * 86400


def _timechart(state: _State, span: Optional[int], by: List[str], pos: int) -> None:
    stamped = []
    for item in state.items:
        t = state.item_epoch(item)
        if t is not None:
            stamped.append((t, item))
    if state.range is not None:
        lo, hi = state.range
    elif stamped:
        lo, hi = min(t for t, _ in stamped), max(t for t, _ in stamped)
    else:
        state.set_rows(["_time", "count"] if not by else ["_time"], [], "timechart")
        return
    if stamped:
        lo, hi = min(lo, min(t for t, _ in stamped)), max(hi, max(t for t, _ in stamped))
    if span is None:
        span = _nice_span((hi - lo) / float(HISTOGRAM_BINS))
    first = math.floor(lo / span)
    nbins = int(math.floor(hi / span)) - first + 1
    if nbins > MAX_TIMECHART_BINS:
        raise SearchError("Too many time buckets; use a larger span", pos)
    get = state.getter(by[0]) if by else None
    cells: List[Counter] = [Counter() for _ in range(nbins)]
    totals: Counter = Counter()
    for t, item in stamped:
        series = "count"
        if get is not None:
            v = get(item)
            series = "NULL" if v is None else _text(_scalar(v))
        cells[int(math.floor(t / span)) - first][series] += 1
        totals[series] += 1
    if get is None:
        names = ["count"]
    else:
        ranked = [s for s, _ in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))]
        names = ranked[:MAX_TIMECHART_SERIES]
        if len(ranked) > len(names):
            names.append("OTHER")
    kept = set(names)
    rows = []
    for i, cell in enumerate(cells):
        row: Dict[str, Any] = {"_time": _iso((first + i) * span)}
        for s in names:
            row[s] = cell.get(s, 0) if s != "OTHER" else sum(c for k, c in cell.items() if k not in kept)
        rows.append(row)
    state.set_rows(["_time"] + names, rows, "timechart")


def _apply(state: _State, pipe: Pipe) -> None:
    a = pipe.args
    if pipe.name == "head":
        state.items = state.items[:a["n"]]
    elif pipe.name == "tail":
        state.items = state.items[-a["n"]:] if a["n"] else []
    elif pipe.name == "sort":
        _sort_items(state, a["keys"])
    elif pipe.name == "dedup":
        _dedup(state, a["fields"])
    elif pipe.name in ("table", "fields"):
        _table(state, a["fields"])
    elif pipe.name == "stats":
        _stats(state, a["aggs"], a["by"])
    elif pipe.name in ("top", "rare"):
        _top(state, a["n"], a["field"], pipe.name == "rare")
    elif pipe.name == "timechart":
        _timechart(state, a["span"], a["by"], pipe.pos)


# ---- result parts ----------------------------------------------------------------------------


def _extent(times: List[float], lo: Optional[float], hi: Optional[float],
            now_epoch: float) -> Optional[Tuple[float, float]]:
    """The time range a chart covers: earliest..latest when given, else the matches."""
    start = lo if lo is not None else (min(times) if times else None)
    if hi is not None:
        end: Optional[float] = hi
    elif lo is not None:
        end = max([now_epoch] + times)
    else:
        end = max(times) if times else None
    if start is None or end is None:
        return None
    if times:
        start, end = min(start, min(times)), max(end, max(times))
    return (start, max(start, end))


def _histogram(stamped: List[Tuple[Optional[float], Dict[str, Any]]],
               rng: Optional[Tuple[float, float]]) -> Dict[str, Any]:
    if rng is None:
        return {"bins": [], "span_s": 0}
    lo, hi = rng
    span = _nice_span((hi - lo) / float(HISTOGRAM_BINS))
    first = math.floor(lo / span)
    nbins = int(math.floor(hi / span)) - first + 1
    counts: List[Counter] = [Counter() for _ in range(nbins)]
    for t, ev in stamped:
        if t is None:
            continue
        src = ev.get("source")
        counts[min(nbins - 1, max(0, int(math.floor(t / span)) - first))][src if isinstance(src, str) else "unknown"] += 1
    bins = [{"start": _iso((first + i) * span), "end": _iso((first + i + 1) * span), "counts": dict(c)}
            for i, c in enumerate(counts)]
    return {"bins": bins, "span_s": span}


def _sidebar(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, Counter] = {}
    present: Counter = Counter()
    for ev in events:
        src = ev.get("source")
        if isinstance(src, str):
            counts.setdefault("source", Counter())[src] += 1
            present["source"] += 1
        fields = ev.get("fields")
        if not isinstance(fields, dict):
            continue
        for name, v in fields.items():
            items = _items(v)
            if not items:
                continue
            present[name] += 1
            c = counts.get(name)
            if c is None:
                c = counts[name] = Counter()
            for x in items:
                t = _text(x)
                if len(t) <= SIDEBAR_VALUE_LEN:
                    c[t] += 1
    out = []
    for name in sorted(present, key=lambda n: (-present[n], n))[:SIDEBAR_FIELDS]:
        top = sorted(counts[name].items(), key=lambda kv: (-kv[1], kv[0]))[:SIDEBAR_VALUES]
        out.append({"name": name, "count": present[name], "top": [{"value": v, "count": c} for v, c in top]})
    return out


def _time_bound(inline: Optional[str], param: Optional[str], now_epoch: float) -> Optional[float]:
    value = inline if inline else (param or None)
    if value is None:
        return None
    epoch = _to_epoch(value, now_epoch)
    if epoch is None:
        raise SearchError(f"Invalid time: {value}")
    return epoch


def run(query: str, events: Iterable[Dict[str, Any]], now: datetime, earliest: Optional[str] = None,
        latest: Optional[str] = None, max_matches: int = 10000, max_rows: int = 1000) -> Dict[str, Any]:
    """Search ``events`` (newest first in the result) and apply the pipes; see the module docstring."""
    q = parse(query)
    now_epoch = _now_epoch(now)
    lo = _time_bound(q.earliest, earliest, now_epoch)
    hi = _time_bound(q.latest, latest, now_epoch)
    pred = _compile(q.terms) if q.terms is not None else None

    matched: List[Tuple[Optional[float], Dict[str, Any]]] = []
    box: List[Optional[str]] = [None]
    timed = lo is not None or hi is not None
    for ev in events:
        if not isinstance(ev, dict):
            continue
        t = None
        if timed:
            t = _event_epoch(ev)
            if t is None or (lo is not None and t < lo) or (hi is not None and t >= hi):
                continue
        if pred is not None:
            box[0] = None
            if not pred(ev, box):
                continue
        if not timed:
            t = _event_epoch(ev)
        matched.append((t, ev))
    matched.sort(key=lambda p: -math.inf if p[0] is None else p[0], reverse=True)

    times = [t for t, _ in matched if t is not None]
    rng = _extent(times, lo, hi, now_epoch)
    histogram = _histogram(matched, rng)

    truncated = False
    working = [ev for _, ev in matched]
    if q.pipes and len(working) > max_matches:
        working = working[:max_matches]
        truncated = True
    sidebar = _sidebar(working[:max_matches])

    state = _State(working, rng)
    for pipe in q.pipes:
        _apply(state, pipe)

    count = len(state.items)
    shown = state.items[:max_rows]
    if count > max_rows:
        truncated = True
    result: Dict[str, Any] = {
        "type": state.kind, "events": [], "columns": None, "rows": [], "count": count,
        "matched": len(matched), "truncated": truncated, "histogram": histogram, "fields": sidebar,
    }
    if state.rows:
        result["columns"] = state.columns
        result["rows"] = [[_finite(row.get(c)) for c in state.columns or []] for row in shown]
    else:
        result["events"] = shown
    return result
