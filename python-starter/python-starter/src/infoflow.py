"""
Information flow analysis for the C0 subset.

Students must implement:
  check_secure(prog) - returns True if secure, False otherwise
"""

import c0


def check_secure(prog: c0.Program) -> bool:
    """Termination-sensitive information flow type checker.

    Returns True if the program is secure, False otherwise.
    """
    LOW = "L"
    HIGH = "H"

    def join(*labels: str) -> str:
        return HIGH if any(lbl == HIGH for lbl in labels) else LOW

    def flows_to(src: str, dst: str) -> bool:
        # Two-point lattice: L <= H
        return not (src == HIGH and dst == LOW)

    def declared_label(raw_label: str | None) -> str:
        if raw_label == HIGH:
            return HIGH
        return LOW

    class TypeErrorIFC(Exception):
        pass

    # Each environment frame maps variable -> (type, security label).
    env_stack: list[dict[str, tuple[c0.Type, str]]] = [
        {
            "input": (c0.IntType(), LOW),
            "secret": (c0.IntType(), HIGH),
        }
    ]

    def lookup_var(name: str) -> tuple[c0.Type, str]:
        for env in reversed(env_stack):
            if name in env:
                return env[name]
        raise TypeErrorIFC(f"undeclared variable `{name}`")

    def infer_exp(exp: c0.Exp) -> tuple[c0.Type, str, str]:
        """
        Returns (type, value_label, abort_label).
        abort_label tracks dependence of whether expression evaluation aborts.
        """
        match exp:
            case c0.IntConst(_):
                return (c0.IntType(), LOW, LOW)

            case c0.BoolConst(_):
                return (c0.BoolType(), LOW, LOW)

            case c0.Var(name):
                typ, lbl = lookup_var(name)
                return (typ, lbl, LOW)

            case c0.UnOp(op, arg):
                t_arg, l_arg, a_arg = infer_exp(arg)
                if op == "-":
                    if not isinstance(t_arg, c0.IntType):
                        raise TypeErrorIFC("unary `-` expects int")
                    return (c0.IntType(), l_arg, a_arg)
                if op == "!":
                    if not isinstance(t_arg, c0.BoolType):
                        raise TypeErrorIFC("`!` expects bool")
                    return (c0.BoolType(), l_arg, a_arg)
                raise TypeErrorIFC(f"unsupported unary operator `{op}`")

            case c0.Length(arg):
                t_arg, l_arg, a_arg = infer_exp(arg)
                if not (isinstance(t_arg, c0.ArrayType) and isinstance(t_arg.base, c0.IntType)):
                    raise TypeErrorIFC("\\length expects int[]")
                # The array label protects both contents and size.
                return (c0.IntType(), l_arg, a_arg)

            case c0.ArrayAccess(arr, index):
                t_arr, l_arr, a_arr = infer_exp(arr)
                t_idx, l_idx, a_idx = infer_exp(index)
                if not (isinstance(t_arr, c0.ArrayType) and isinstance(t_arr.base, c0.IntType)):
                    raise TypeErrorIFC("array access expects int[]")
                if not isinstance(t_idx, c0.IntType):
                    raise TypeErrorIFC("array index must be int")
                # Reading element can reveal both array and index.
                val_label = join(l_arr, l_idx)
                # Bounds-check abort depends on array/index labels and subexpression abort.
                abort_label = join(a_arr, a_idx, l_arr, l_idx)
                return (c0.IntType(), val_label, abort_label)

            case c0.BinOp(op, left, right):
                t_l, l_l, a_l = infer_exp(left)
                t_r, l_r, a_r = infer_exp(right)
                arith = {"+", "-", "*", "/", "%"}
                cmp_ops = {"<", "<=", ">", ">="}
                logic = {"&&", "||"}
                eq_ops = {"==", "!="}

                if op in arith:
                    if not isinstance(t_l, c0.IntType) or not isinstance(t_r, c0.IntType):
                        raise TypeErrorIFC(f"`{op}` expects int operands")
                    val_label = join(l_l, l_r)
                    abort_label = join(a_l, a_r)
                    if op in {"/", "%"}:
                        # Division/modulo may abort when divisor is 0.
                        abort_label = join(abort_label, l_r)
                    return (c0.IntType(), val_label, abort_label)

                if op in cmp_ops:
                    if not isinstance(t_l, c0.IntType) or not isinstance(t_r, c0.IntType):
                        raise TypeErrorIFC(f"`{op}` expects int operands")
                    return (c0.BoolType(), join(l_l, l_r), join(a_l, a_r))

                if op in eq_ops:
                    if type(t_l) is not type(t_r):
                        raise TypeErrorIFC(f"`{op}` expects same-typed operands")
                    return (c0.BoolType(), join(l_l, l_r), join(a_l, a_r))

                if op in logic:
                    if not isinstance(t_l, c0.BoolType) or not isinstance(t_r, c0.BoolType):
                        raise TypeErrorIFC(f"`{op}` expects bool operands")
                    # Short-circuit: whether right is evaluated depends on left value.
                    abort_label = join(a_l, l_l, a_r)
                    return (c0.BoolType(), join(l_l, l_r), abort_label)

                raise TypeErrorIFC(f"unsupported binary operator `{op}`")

            case _:
                raise TypeErrorIFC(f"unsupported expression form: {type(exp)}")

    def require_flows(src: str, dst: str) -> None:
        if not flows_to(src, dst):
            raise TypeErrorIFC(f"illegal flow {src} -> {dst}")

    def check_stmt(stmt: c0.Stmt, pc: str) -> None:
        match stmt:
            case c0.Decl(typ, name, init, label=lbl):
                var_label = declared_label(lbl)
                if init is not None:
                    t_init, l_init, a_init = infer_exp(init)
                    if type(t_init) is not type(typ):
                        raise TypeErrorIFC("initializer type mismatch")
                    require_flows(join(pc, l_init), var_label)
                    # Abort in initializer must not encode secrets.
                    require_flows(join(pc, a_init), LOW)
                env_stack[-1][name] = (typ, var_label)

            case c0.Assign(dest, source):
                t_dest, l_dest = lookup_var(dest)
                t_src, l_src, a_src = infer_exp(source)
                if type(t_dest) is not type(t_src):
                    raise TypeErrorIFC("assignment type mismatch")
                require_flows(join(pc, l_src), l_dest)
                require_flows(join(pc, a_src), LOW)

            case c0.AllocArray(dest, _typ, count, label=_):
                t_dest, l_dest = lookup_var(dest)
                if not (isinstance(t_dest, c0.ArrayType) and isinstance(t_dest.base, c0.IntType)):
                    raise TypeErrorIFC("alloc_array destination must be int[]")
                t_count, l_count, a_count = infer_exp(count)
                if not isinstance(t_count, c0.IntType):
                    raise TypeErrorIFC("alloc_array count must be int")
                # Array length is protected by the array label.
                require_flows(join(pc, l_count), l_dest)
                require_flows(join(pc, a_count), LOW)

            case c0.ArrWrite(arr, index, val):
                # Parser/typechecker ensures arr is variable form, keep defensive check.
                if not isinstance(arr, c0.Var):
                    raise TypeErrorIFC("array write expects variable base")
                t_arr, l_arr = lookup_var(arr.name)
                if not (isinstance(t_arr, c0.ArrayType) and isinstance(t_arr.base, c0.IntType)):
                    raise TypeErrorIFC("array write destination must be int[]")

                t_idx, l_idx, a_idx = infer_exp(index)
                t_val, l_val, a_val = infer_exp(val)
                if not isinstance(t_idx, c0.IntType):
                    raise TypeErrorIFC("array index must be int")
                if not isinstance(t_val, c0.IntType):
                    raise TypeErrorIFC("array value must be int")

                # Whole-array label protects element updates and index-based effects.
                require_flows(join(pc, l_idx, l_val), l_arr)
                # Bounds-check abort + subexpression abort must be low-observable-safe.
                require_flows(join(pc, a_idx, a_val, l_arr, l_idx), LOW)

            case c0.Block(stmts):
                env_stack.append({})
                for s in stmts:
                    check_stmt(s, pc)
                env_stack.pop()

            case c0.If(cond, t_branch, f_branch):
                t_cond, l_cond, a_cond = infer_exp(cond)
                if not isinstance(t_cond, c0.BoolType):
                    raise TypeErrorIFC("if condition must be bool")
                require_flows(join(pc, a_cond), LOW)

                pc_branch = join(pc, l_cond)
                check_stmt(t_branch, pc_branch)
                if f_branch is not None:
                    check_stmt(f_branch, pc_branch)

            case c0.While(cond, _invs, body):
                t_cond, l_cond, a_cond = infer_exp(cond)
                if not isinstance(t_cond, c0.BoolType):
                    raise TypeErrorIFC("while condition must be bool")
                # Termination-sensitive rule: loop guard must be low under current pc.
                require_flows(join(pc, l_cond), LOW)
                require_flows(join(pc, a_cond), LOW)
                check_stmt(body, join(pc, l_cond))

            case c0.Assert(cond):
                t_cond, l_cond, a_cond = infer_exp(cond)
                if not isinstance(t_cond, c0.BoolType):
                    raise TypeErrorIFC("assert condition must be bool")
                # assert may abort when cond is false.
                require_flows(join(pc, l_cond, a_cond), LOW)

            case c0.Error(_msg):
                # error always aborts; only safe when not control-dependent on high data.
                require_flows(pc, LOW)

            case c0.Return(val):
                if val is None:
                    raise TypeErrorIFC("return expects expression")
                t_ret, l_ret, a_ret = infer_exp(val)
                if not isinstance(t_ret, c0.IntType):
                    raise TypeErrorIFC("main must return int")
                # Return is a low observation.
                require_flows(join(pc, l_ret), LOW)
                require_flows(join(pc, a_ret), LOW)

            case _:
                raise TypeErrorIFC(f"unsupported statement form: {type(stmt)}")

    try:
        for st in prog.stmts:
            check_stmt(st, LOW)
    except TypeErrorIFC:
        return False
    except Exception:
        # Conservative fallback: reject on unexpected analyzer failure.
        return False

    return True
