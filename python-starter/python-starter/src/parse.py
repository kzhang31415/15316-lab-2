import c0
import pyparsing
from pyparsing import (
    Word, nums, alphas, alphanums, Combine, Literal, Keyword,
    Optional, OneOrMore, ZeroOrMore, Forward, Suppress,
    infixNotation, opAssoc, ParserElement, Regex, QuotedString, Group,
    LineEnd, LineStart, SkipTo
)
import re
from typing import List, Tuple

ParserElement.enable_packrat()


def file_parse(text: str) -> c0.Program:
    NormalComment = Regex(r"//(?![@]).*")
    BlockComment = Regex(r"/\*.*?\*/", flags=re.DOTALL)

    # Keywords
    INT = Keyword("int")
    BOOL = Keyword("bool")
    TRUE = Keyword("true")
    FALSE = Keyword("false")
    ALLOC_ARRAY = Keyword("alloc_array")
    IF = Keyword("if")
    ELSE = Keyword("else")
    WHILE = Keyword("while")
    ASSERT = Keyword("assert")
    ERROR = Keyword("error")
    RETURN = Keyword("return")

    # Contract keywords
    ANNOTATION_START = Literal("//@")
    LOOP_INVARIANT = Keyword("loop_invariant")
    C_ASSERT = Keyword("assert")
    REQUIRES = Keyword("requires")
    LABEL = Keyword("label")

    # Punctuation
    LPAREN = Suppress("(")
    RPAREN = Suppress(")")
    LBRACE = Suppress("{")
    RBRACE = Suppress("}")
    LBRACKET = Suppress("[")
    RBRACKET = Suppress("]")
    SEMI = Suppress(";")
    COMMA = Suppress(",")
    ASSIGN_OP = Literal("=")

    # Identifiers
    Ident = Word(alphas, alphanums + "_")
    Reserved = (INT | BOOL | TRUE | FALSE | ALLOC_ARRAY | IF | ELSE |
                WHILE | ASSERT | ERROR | RETURN | REQUIRES |
                LOOP_INVARIANT | Keyword("main"))

    Identifier = (~Reserved + Ident).setParseAction(lambda t: t[0])
    VarIdent = Identifier.copy().setParseAction(lambda t: c0.Var(t[0]))

    # Types
    Type = Forward()
    IntType = INT.copy().setParseAction(lambda _: c0.IntType())
    BoolType = BOOL.copy().setParseAction(lambda _: c0.BoolType())
    IntArrayType = (INT + Literal("[]")).setParseAction(lambda _: c0.ArrayType(c0.IntType()))
    Type <<= (IntArrayType | IntType | BoolType)

    # Forward declarations
    Exp = Forward()
    Stmt = Forward()

    # Atoms
    SafeInt = Word(nums).setParseAction(lambda t: c0.IntConst(int(t[0])))
    SafeBool = (TRUE | FALSE).setParseAction(lambda t: c0.BoolConst(t[0] == "true"))

    def _reject_null(s, loc, _toks):
        raise pyparsing.ParseFatalException(s, loc, "NULL is not supported")

    BaseAtom = (
        SafeInt | SafeBool | VarIdent | (LPAREN + Exp + RPAREN)
    )

    def reduce_index(t):
        res = t[0]
        for i in range(1, len(t)):
            res = c0.ArrayAccess(res, t[i])
        return res

    AtomWithArray = (BaseAtom + ZeroOrMore(LBRACKET + Exp + RBRACKET)).setParseAction(
        lambda t: reduce_index(t)
    )

    def make_binop(t):
        tokens = t[0]
        res = tokens[0]
        i = 1
        while i < len(tokens):
            op = tokens[i]
            rhs = tokens[i + 1]
            res = c0.BinOp(op, res, rhs)
            i += 2
        return res

    def make_unop(t):
        op = t[0][0]
        arg = t[0][1]
        if op == "\\length":
            return c0.Length(arg)
        return c0.UnOp(op, arg)

    LENGTH = Literal("\\length")

    Exp <<= infixNotation(AtomWithArray, [
        (Literal("!") | LENGTH, 1, opAssoc.RIGHT, make_unop),
        (Literal("-"), 1, opAssoc.RIGHT, make_unop),
        (Literal("*") | Literal("/") | Literal("%"), 2, opAssoc.LEFT, make_binop),
        (Literal("+") | Literal("-"), 2, opAssoc.LEFT, make_binop),
        (Literal("<=") | Literal(">=") | Literal("<") | Literal(">"), 2, opAssoc.LEFT, make_binop),
        (Literal("==") | Literal("!="), 2, opAssoc.LEFT, make_binop),
        (Literal("&&"), 2, opAssoc.LEFT, make_binop),
        (Literal("||"), 2, opAssoc.LEFT, make_binop),
    ])

    # --- Statements ---

    def flatten(t):
        res = []
        for x in t:
            if isinstance(x, list):
                res.extend(flatten(x))
            else:
                res.append(x)
        return res

    # Label annotation: //@label H or //@label L
    # This is parsed as part of declaration statements.
    LabelAnnotation = (ANNOTATION_START + LABEL + (Literal("H") | Literal("L")) + SEMI).setParseAction(
        lambda t: t[2]
    )

    # Declaration with optional label annotation preceding it
    DeclStmt = (Optional(LabelAnnotation)("label") +
                Type + Identifier + Optional(ASSIGN_OP + Exp) + SEMI).setParseAction(
        lambda t: c0.Decl(
            t.label[0] if t.label else None,  # reordered below
            t[1] if t.label else t[0],
            t[2] if t.label else t[1],
            t[4] if t.label and len(t) > 4 else (t[3] if not t.label and len(t) > 3 else None),
        )
    )

    # This is getting complex with optional label. Let me restructure.
    # A declaration can optionally be preceded by //@label H; or //@label L;
    # and can optionally have an initializer.

    def make_decl(t):
        tokens = list(t)
        label = None
        idx = 0
        if isinstance(tokens[0], str) and tokens[0] in ("H", "L"):
            label = tokens[0]
            idx = 1
        typ = tokens[idx]
        name = tokens[idx + 1]
        init = tokens[idx + 3] if len(tokens) > idx + 3 else None
        return c0.Decl(typ, name, init, label=label)

    DeclStmt = (Optional(LabelAnnotation) +
                Type + Identifier + Optional(ASSIGN_OP + Exp) + SEMI).setParseAction(make_decl)

    # Handle int[] x = alloc_array(...)
    def make_alloc_decl(t):
        tokens = list(t)
        label = None
        idx = 0
        if isinstance(tokens[0], str) and tokens[0] in ("H", "L"):
            label = tokens[0]
            idx = 1
        typ = tokens[idx]
        name = tokens[idx + 1]
        count = tokens[idx + 5]
        return [c0.Decl(typ, name, None, label=label), c0.AllocArray(name, c0.IntType(), count, label=label)]

    DeclAllocStmt = (Optional(LabelAnnotation) +
                     Type + Identifier + ASSIGN_OP + ALLOC_ARRAY + LPAREN + INT + COMMA + Exp + RPAREN + SEMI
                     ).setParseAction(make_alloc_decl)

    def make_assign(t):
        lhs = t[0]
        rhs = t[2]
        if isinstance(lhs, c0.Var):
            return c0.Assign(lhs.name, rhs)
        elif isinstance(lhs, c0.ArrayAccess):
            return c0.ArrWrite(lhs.arr, lhs.index, rhs)
        else:
            raise pyparsing.ParseException(f"Invalid assignment target: {lhs}")

    AssignStmt = (AtomWithArray + ASSIGN_OP + Exp + SEMI).setParseAction(make_assign)

    AllocArrayStmt = (Identifier + ASSIGN_OP + ALLOC_ARRAY + LPAREN + INT + COMMA + Exp + RPAREN + SEMI).setParseAction(
        lambda t: c0.AllocArray(t[0], c0.IntType(), t[4])
    )

    Block = (LBRACE - ZeroOrMore(Stmt) + RBRACE).setParseAction(
        lambda t: c0.Block(flatten(t))
    )

    IfStmt = (IF - LPAREN + Exp + RPAREN + Stmt + Optional(ELSE + Stmt)).setParseAction(
        lambda t: c0.If(t[1], t[2], t[4] if len(t) > 4 else None)
    )

    WhileStmt = (WHILE - LPAREN + Exp + RPAREN +
                 ZeroOrMore(
                     (ANNOTATION_START + LOOP_INVARIANT + Exp + SEMI).setParseAction(lambda t: t[2])
                 ) +
                 Stmt).setParseAction(
        lambda t: c0.While(t[1], list(t[2:-1]), t[-1])
    )

    AssertStmt = (ASSERT + LPAREN + Exp + RPAREN + SEMI).setParseAction(
        lambda t: c0.Assert(t[1])
    )

    ContractAssertStmt = (ANNOTATION_START + C_ASSERT + Exp + SEMI).setParseAction(
        lambda t: c0.Assert(t[2])
    )

    StringLit = QuotedString('"')
    ErrorStmt = (ERROR + LPAREN + StringLit + RPAREN + SEMI).setParseAction(
        lambda t: c0.Error(t[1])
    )

    ReturnStmt = (RETURN + Exp + SEMI).setParseAction(
        lambda t: c0.Return(t[1])
    )

    Stmt <<= (
        Block |
        DeclAllocStmt |
        DeclStmt |
        IfStmt |
        WhileStmt |
        AssertStmt |
        ContractAssertStmt |
        ErrorStmt |
        ReturnStmt |
        AllocArrayStmt |
        AssignStmt
    )

    ContractRaw = Group(ANNOTATION_START + REQUIRES("kind") + Exp("cond") + SEMI)

    def _is_int_type(typ):
        return isinstance(typ, c0.IntType)

    def parse_main(s, loc, t):
        # Enforce: int main(int input, int secret)
        if not _is_int_type(t.ret_type):
            raise pyparsing.ParseFatalException(s, loc, "main must return int")
        if not _is_int_type(t.arg1_type) or t.arg1_name != "input":
            raise pyparsing.ParseFatalException(
                s, loc,
                f"first argument must be `int input` (got `{t.arg1_type} {t.arg1_name}`)",
            )
        if not _is_int_type(t.arg2_type) or t.arg2_name != "secret":
            raise pyparsing.ParseFatalException(
                s, loc,
                f"second argument must be `int secret` (got `{t.arg2_type} {t.arg2_name}`)",
            )

        stmts = t.body.stmts

        # Exactly one return, at top-level end of main body.
        if len(stmts) == 0 or not isinstance(stmts[-1], c0.Return):
            raise pyparsing.ParseFatalException(
                s, loc, "main must end with a single top-level return statement")
        for st in stmts[:-1]:
            if _stmt_contains_return(st):
                raise pyparsing.ParseFatalException(
                    s, loc, "main must contain exactly one return statement at top level")

        reqs = []
        for c in t.contracts:
            reqs.append(c.cond)

        return c0.Program(stmts, requires=reqs, args=[t.arg1_name, t.arg2_name])

    def _stmt_contains_return(s):
        match s:
            case c0.Return(_):
                return True
            case c0.Block(stmts):
                return any(_stmt_contains_return(x) for x in stmts)
            case c0.If(_, t, f):
                return _stmt_contains_return(t) or (f is not None and _stmt_contains_return(f))
            case c0.While(_, _, body):
                return _stmt_contains_return(body)
            case _:
                return False

    MainFunc = (
        Type("ret_type") + Keyword("main") - LPAREN +
        Type("arg1_type") + Identifier("arg1_name") + COMMA +
        Type("arg2_type") + Identifier("arg2_name") + RPAREN +
        ZeroOrMore(ContractRaw)("contracts") +
        Block("body")
    ).setParseAction(parse_main)

    ProgramParser = MainFunc

    ProgramParser.ignore(NormalComment)
    ProgramParser.ignore(BlockComment)

    try:
        prog = ProgramParser.parseString(text, parseAll=True)[0]
        _typecheck_and_validate_program(text, prog)
        return prog
    except pyparsing.ParseException as e:
        raise e


def _typecheck_and_validate_program(src: str, prog: c0.Program) -> None:
    """
    Enforce lab-specific syntactic restrictions and basic type checks.
    Includes no-aliasing restriction for arrays.
    """

    def fatal(msg: str) -> None:
        raise pyparsing.ParseFatalException(src, 0, msg)

    def is_int(t: c0.Type) -> bool:
        return isinstance(t, c0.IntType)

    def is_bool(t: c0.Type) -> bool:
        return isinstance(t, c0.BoolType)

    def is_int_array(t: c0.Type) -> bool:
        return isinstance(t, c0.ArrayType) and isinstance(t.base, c0.IntType)

    def lookup(env_stack, name):
        for env in reversed(env_stack):
            if name in env:
                return env[name]
        fatal(f"use of undeclared variable `{name}`")

    def exp_type(env_stack, e):
        match e:
            case c0.IntConst(_):
                return c0.IntType()
            case c0.BoolConst(_):
                return c0.BoolType()
            case c0.Var(name):
                return lookup(env_stack, name)

            case c0.Length(arg):
                t_arg = exp_type(env_stack, arg)
                if not is_int_array(t_arg):
                    fatal("\\length expects an `int[]` expression")
                return c0.IntType()

            case c0.ArrayAccess(arr, idx):
                t_arr = exp_type(env_stack, arr)
                t_idx = exp_type(env_stack, idx)
                if not is_int_array(t_arr):
                    fatal("array indexing expects an `int[]` base expression")
                if not is_int(t_idx):
                    fatal("array index must have type `int`")
                return c0.IntType()

            case c0.UnOp(op, arg):
                t_arg = exp_type(env_stack, arg)
                if op == "!":
                    if not is_bool(t_arg):
                        fatal("`!` expects a `bool` operand")
                    return c0.BoolType()
                if op == "-":
                    if not is_int(t_arg):
                        fatal("unary `-` expects an `int` operand")
                    return c0.IntType()
                fatal(f"unknown unary operator `{op}`")

            case c0.BinOp(op, l, r):
                t_l = exp_type(env_stack, l)
                t_r = exp_type(env_stack, r)

                arith = {"+", "-", "*", "/", "%"}
                cmp_ops = {"<", "<=", ">", ">="}
                logic = {"&&", "||"}
                eq = {"==", "!="}

                if op in arith:
                    if not (is_int(t_l) and is_int(t_r)):
                        fatal(f"`{op}` expects `int` operands")
                    return c0.IntType()
                if op in cmp_ops:
                    if not (is_int(t_l) and is_int(t_r)):
                        fatal(f"`{op}` expects `int` operands")
                    return c0.BoolType()
                if op in logic:
                    if not (is_bool(t_l) and is_bool(t_r)):
                        fatal(f"`{op}` expects `bool` operands")
                    return c0.BoolType()
                if op in eq:
                    if type(t_l) is not type(t_r):
                        fatal(f"`{op}` expects operands of the same type")
                    return c0.BoolType()

                fatal(f"unknown binary operator `{op}`")

            case _:
                fatal(f"unsupported expression form: {type(e)}")

    def check_stmt(env_stack, s):
        match s:
            case c0.Decl(typ, name, init, label=label):
                if label is not None and label not in ("H", "L"):
                    fatal(f"invalid label `{label}` on declaration of `{name}`")
                if is_int_array(typ) and init is not None:
                    fatal("`int[]` variables cannot be initialized by assignment; use `alloc_array`")
                if init is not None:
                    t_init = exp_type(env_stack, init)
                    if type(t_init) is not type(typ):
                        fatal(f"type mismatch in initializer for `{name}`")
                env_stack[-1][name] = typ

            case c0.Assign(dest, src):
                t_dest = lookup(env_stack, dest)
                if is_int_array(t_dest):
                    fatal("assignment between `int[]` variables is not allowed")
                t_src = exp_type(env_stack, src)
                if type(t_src) is not type(t_dest):
                    fatal(f"type mismatch in assignment to `{dest}`")

            case c0.AllocArray(dest, typ, count, label=_):
                t_dest = lookup(env_stack, dest)
                if not is_int_array(t_dest):
                    fatal("`alloc_array` destination must have type `int[]`")
                if not isinstance(typ, c0.IntType):
                    fatal("only `alloc_array(int, n)` is supported")
                if not is_int(exp_type(env_stack, count)):
                    fatal("`alloc_array` count must have type `int`")

            case c0.ArrWrite(arr, idx, val):
                if not isinstance(arr, c0.Var):
                    fatal("array write must have the form `A[i] = e` where `A` is a variable")
                t_arr = lookup(env_stack, arr.name)
                if not is_int_array(t_arr):
                    fatal("array write expects an `int[]` base variable")
                if not is_int(exp_type(env_stack, idx)):
                    fatal("array index must have type `int`")
                if not is_int(exp_type(env_stack, val)):
                    fatal("array element value must have type `int`")

            case c0.If(cond, t, f):
                if not is_bool(exp_type(env_stack, cond)):
                    fatal("`if` condition must have type `bool`")
                env_stack.append({})
                check_stmt(env_stack, t)
                env_stack.pop()
                if f is not None:
                    env_stack.append({})
                    check_stmt(env_stack, f)
                    env_stack.pop()

            case c0.While(cond, invs, body):
                if not is_bool(exp_type(env_stack, cond)):
                    fatal("`while` condition must have type `bool`")
                for inv in invs:
                    if not is_bool(exp_type(env_stack, inv)):
                        fatal("loop invariants must have type `bool`")
                env_stack.append({})
                check_stmt(env_stack, body)
                env_stack.pop()

            case c0.Block(stmts):
                env_stack.append({})
                for st in stmts:
                    check_stmt(env_stack, st)
                env_stack.pop()

            case c0.Assert(cond):
                if not is_bool(exp_type(env_stack, cond)):
                    fatal("`assert` condition must have type `bool`")

            case c0.Return(val):
                if val is None:
                    fatal("main must return an `int` expression")
                if not is_int(exp_type(env_stack, val)):
                    fatal("main must return an `int` expression")

            case c0.Error(_):
                return

            case _:
                fatal(f"unsupported statement form: {type(s)}")

    env_stack = [{}]
    if prog.args and len(prog.args) == 2:
        env_stack[-1][prog.args[0]] = c0.IntType()
        env_stack[-1][prog.args[1]] = c0.IntType()

    for e in (prog.requires or []):
        if not is_bool(exp_type(env_stack, e)):
            fatal("requires clauses must be boolean formulas")

    for st in prog.stmts:
        check_stmt(env_stack, st)
