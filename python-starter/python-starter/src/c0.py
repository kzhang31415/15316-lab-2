from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Type:
    pass


@dataclass
class IntType(Type):
    def __repr__(self):
        return "int"


@dataclass
class BoolType(Type):
    def __repr__(self):
        return "bool"


@dataclass
class ArrayType(Type):
    base: Type

    def __repr__(self):
        return f"{self.base}[]"


@dataclass
class Node:
    pass


@dataclass
class Exp(Node):
    pass


@dataclass
class IntConst(Exp):
    value: int


@dataclass
class BoolConst(Exp):
    value: bool


@dataclass
class Var(Exp):
    name: str


@dataclass
class BinOp(Exp):
    op: str
    left: Exp
    right: Exp


@dataclass
class UnOp(Exp):
    op: str
    arg: Exp


@dataclass
class Length(Exp):
    arg: Exp


@dataclass
class ArrayAccess(Exp):
    arr: Exp
    index: Exp


@dataclass
class Stmt(Node):
    pass


@dataclass
class Decl(Stmt):
    type: Type
    name: str
    init: Optional[Exp]
    label: Optional[str] = None  # "H" or "L" from //@label annotation; None = default (L)


@dataclass
class Assign(Stmt):
    dest: str
    source: Exp


@dataclass
class AllocArray(Stmt):
    dest: str
    type: Type
    count: Exp
    label: Optional[str] = None  # "H" or "L" from //@label annotation; None = default (L)


@dataclass
class ArrRead(Stmt):
    dest: str
    arr: Exp
    index: Exp


@dataclass
class ArrWrite(Stmt):
    arr: Exp
    index: Exp
    val: Exp


@dataclass
class Block(Stmt):
    stmts: List[Stmt]


@dataclass
class If(Stmt):
    cond: Exp
    true_branch: Stmt
    false_branch: Optional[Stmt]


@dataclass
class While(Stmt):
    cond: Exp
    invariants: List[Exp]
    body: Stmt


@dataclass
class Assert(Stmt):
    cond: Exp


@dataclass
class Error(Stmt):
    msg: str


@dataclass
class Return(Stmt):
    val: Optional[Exp]


@dataclass
class Program(Node):
    stmts: List[Stmt]
    requires: List[Exp] = field(default_factory=list)
    args: List[str] = field(default_factory=list)  # ["input", "secret"]
