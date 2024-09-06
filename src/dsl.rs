use core::panic;
use std::collections::HashMap;

use regex::Regex;

#[derive(Debug, Copy, Clone)]
pub enum OPCode {
    // Basic Operators
    LoadVar = 1,
    LoadConstStr = 2,
    LoadConstShort = 3, // 16 bit
    LoadConstInt = 4,   // 64 bit
    LoadConstBoolTrue = 5, 
    LoadConstBoolFalse = 6,
    CallFunc = 7,

    // Comparison Operators
    CmpGt = 8,
    CmpGtEq = 9,
    CmpEq = 10,
    CmpNeq = 11,
    CmpLtEq = 12,
    CmpLt = 13,

    // Binary Operators
    Add = 14,
    Sub = 15,
    Mul = 16,
    Div = 17,
    BinAnd = 18,
    BinOr = 19,
    Exp = 20,
    Mod = 21,
    Xor = 22,
    Shl = 23,
    Shr = 24,

    // Logical Operators
    And = 25,
    Or = 26,
    In = 27,

    // Special Operators
    RegEq = 28,
    RegNeq = 29,
    Invert = 30, // Invert/Negate top bool/int on stack
    BitwiseNot = 31,

    // Branching Operators
    ShortJump = 32, // pops bool off stack, if true jump forward by (-32768, 32767) instructions/values
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    String(String),
    Int(i64),
    Short(i16),
    Boolean(bool),
}

#[derive(Debug)]
pub enum Bytecode {
    Instr(OPCode),
    Value(Value),
}

#[derive(Debug)]
pub struct CompiledExpression(Vec<Bytecode>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operator {
    // Comparator Ops
    Eq,
    Neq,
    Gt,
    GtEq,
    Lt,
    LtEq,
    RegexEq,
    RegexNeq,
    // Binary Ops
    In,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Exp,
    BitAnd,
    BitOr,
    Xor,
    Shl,
    Shr,
    // Logical Ops
    And,
    Or,
    //Special
    Invert,
    BitwiseNot,
}

#[derive(Debug)]
pub enum Expr {
    Operator(Box<Expr>, Operator, Box<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    Function(String, Vec<Expr>),
    Constant(Value),
    Variable(String),
    List(Vec<Expr>),
    Prefix(Operator, Box<Expr>),
}

pub fn optimize_expr(expr: Expr) -> Expr {
    match expr {
        Expr::Operator(left, op, right) => {
            let optimized_left = optimize_expr(*left);
            let optimized_right = optimize_expr(*right);

            if op == Operator::And {
                if let Expr::Constant(Value::Boolean(l_b)) = optimized_left {
                    if l_b {
                        return optimized_right;
                    }
                }
                if let Expr::Constant(Value::Boolean(r_b)) = optimized_right {
                    if r_b {
                        return optimized_left;
                    }
                }
            }
            if op == Operator::Or {
                if let Expr::Constant(Value::Boolean(l_b)) = optimized_left {
                    if l_b {
                        return Expr::Constant(Value::Boolean(true));
                    }
                }
                // Only fold left side, since (func() || true) needs to evaluate func
            }

            if let Expr::Constant(l) = &optimized_left {
                if let Expr::Constant(r) = &optimized_right {
                    if op == Operator::Eq {
                        return Expr::Constant(Value::Boolean(l == r));
                    }
                    if op == Operator::Neq {
                        return Expr::Constant(Value::Boolean(l != r));
                    }

                    // Integer optimizations
                    if let Value::Int(l_i) = l {
                        if let Value::Int(r_i) = r {
                            return match op {
                                Operator::Add => Expr::Constant(Value::Int(l_i + r_i)),
                                Operator::Mul => Expr::Constant(Value::Int(l_i * r_i)),
                                Operator::Div => Expr::Constant(Value::Int(l_i / r_i)),
                                Operator::Gt => Expr::Constant(Value::Boolean(l_i > r_i)),
                                Operator::GtEq => Expr::Constant(Value::Boolean(l_i >= r_i)),
                                Operator::Lt => Expr::Constant(Value::Boolean(l_i < r_i)),
                                Operator::LtEq => Expr::Constant(Value::Boolean(l_i <= r_i)),
                                _ => Expr::Operator(
                                    Box::new(optimized_left),
                                    op,
                                    Box::new(optimized_right),
                                ),
                            };
                        }
                    }

                    // Boolean optimizations
                    if let Value::Boolean(l_b) = l {
                        if let Value::Boolean(r_b) = r {
                            return match op {
                                Operator::And => Expr::Constant(Value::Boolean(*l_b && *r_b)),
                                Operator::Or => Expr::Constant(Value::Boolean(*l_b || *r_b)),
                                _ => Expr::Operator(
                                    Box::new(optimized_left),
                                    op,
                                    Box::new(optimized_right),
                                ),
                            };
                        }
                    }
                }
            }

            Expr::Operator(Box::new(optimized_left), op, Box::new(optimized_right))
        }
        Expr::Prefix(op, expr) => {
            let optimized = optimize_expr(*expr);
            match optimized {
                Expr::Constant(Value::Boolean(b)) => {
                    if op == Operator::Invert {
                        return Expr::Constant(Value::Boolean(!b));
                    }
                }
                Expr::Constant(Value::Int(i)) => {
                    if op == Operator::Invert {
                        return Expr::Constant(Value::Int(-i));
                    }
                }
                _ => {}
            }
            Expr::Prefix(op, Box::new(optimized))
        }
        Expr::Function(name, args) => Expr::Function(
            name,
            args.into_iter().map(|arg| optimize_expr(arg)).collect(),
        ),
        Expr::List(args) => Expr::List(args.into_iter().map(|arg| optimize_expr(arg)).collect()),
        _ => expr,
    }
}

fn map_op(op: Operator) -> OPCode {
    match op {
        Operator::And => OPCode::And,
        Operator::Or => OPCode::Or,
        Operator::Add => OPCode::Add,
        Operator::Eq => OPCode::CmpEq,
        Operator::Neq => OPCode::CmpNeq,
        Operator::Gt => OPCode::CmpGt,
        Operator::GtEq => OPCode::CmpGtEq,
        Operator::Lt => OPCode::CmpLt,
        Operator::LtEq => OPCode::CmpLtEq,
        Operator::In => OPCode::In, // TODO: Handle differently
        Operator::BitAnd => OPCode::BinAnd,
        Operator::BitOr => OPCode::BinOr,
        Operator::Div => OPCode::Div,
        Operator::Exp => OPCode::Exp,
        Operator::Mod => OPCode::Mod,
        Operator::Sub => OPCode::Sub,
        Operator::Mul => OPCode::Mul,
        Operator::Xor => OPCode::Xor,
        Operator::Shl => OPCode::Shl,
        Operator::Shr => OPCode::Shr,
        Operator::RegexEq => OPCode::RegEq,
        Operator::RegexNeq => OPCode::RegNeq,
        Operator::Invert => OPCode::Invert,
        Operator::BitwiseNot => OPCode::BitwiseNot,
    }
}

pub fn compile_bytecode(expr: Expr) -> CompiledExpression {
    // For now we give everything left-presidence

    match expr {
        Expr::Operator(left, op, right) => {
            let mut ops = Vec::new();
            ops.append(&mut compile_bytecode(*left).0);
            ops.append(&mut compile_bytecode(*right).0);
            ops.push(Bytecode::Instr(map_op(op)));

            CompiledExpression(ops)
        }
        Expr::Function(name, variables) => {
            let mut ops = Vec::new();

            for e in variables {
                ops.append(&mut compile_bytecode(e).0);
            }
            ops.push(Bytecode::Instr(OPCode::CallFunc));
            ops.push(Bytecode::Value(Value::String(name)));

            CompiledExpression(ops)
        }
        Expr::Ternary(left, middle, right) => {
            let mut ops = Vec::new();

            let mut middle = compile_bytecode(*middle).0;
            let mut right = compile_bytecode(*right).0;

            // Left expression so we end up with a boolean on top of the stack
            ops.append(&mut compile_bytecode(*left).0);
            ops.push(Bytecode::Instr(OPCode::Invert)); // Jump if false, so invert bool

            // Jump over middle part
            ops.push(Bytecode::Instr(OPCode::ShortJump));

            // Jump over right part, if we take middle path
            middle.push(Bytecode::Instr(OPCode::LoadConstBoolTrue)); // unconditional jump
            middle.push(Bytecode::Instr(OPCode::ShortJump));
            middle.push(Bytecode::Value(Value::Short(right.len() as i16)));

            ops.push(Bytecode::Value(Value::Short(middle.len() as i16))); // + 3 to adjust for Jump out of middle
            
            ops.append(&mut middle);
            ops.append(&mut right);

            CompiledExpression(ops)
        }
        Expr::Constant(Value::Boolean(val)) => CompiledExpression(vec![Bytecode::Instr(if val { OPCode::LoadConstBoolTrue } else { OPCode::LoadConstBoolFalse})]),
        Expr::Constant(value) => {
            let op = match value {
                Value::String(_) => OPCode::LoadConstStr,
                Value::Int(_) => OPCode::LoadConstInt,
                _ => unreachable!("not possible")
            };
            CompiledExpression(vec![Bytecode::Instr(op), Bytecode::Value(value)])
        }
        Expr::Prefix(op, expr) => {
            let mut ops = Vec::new();
            ops.append(&mut compile_bytecode(*expr).0);
            ops.push(Bytecode::Instr(map_op(op)));

            CompiledExpression(ops)
        }
        Expr::List(args) => {
            // Push list elements onto stack in the opposite direction, last element first
            // Finally, we push the length of the List onto the stack
            let mut ops = Vec::new();
            let count = args.len();
            for e in args.into_iter().rev() {
                ops.append(&mut compile_bytecode(e).0);
            }
            ops.push(Bytecode::Instr(OPCode::LoadConstShort));
            ops.push(Bytecode::Value(Value::Short(count as i16)));

            CompiledExpression(ops)
        }
        Expr::Variable(value) => CompiledExpression(vec![
            Bytecode::Instr(OPCode::LoadVar),
            Bytecode::Value(Value::String(value)),
        ]),
    }
}

pub fn bytecode_to_binary(bytecode: &CompiledExpression) -> Vec<u8> {
    let mut bytes = Vec::new();
    for cur in &bytecode.0 {
        match cur {
            Bytecode::Instr(instr) => {
                bytes.push(*instr as u8);
            }
            Bytecode::Value(value) => match value {
                Value::Boolean(value) => {
                    bytes.push(*value as u8);
                }
                Value::Int(value) => {
                    bytes.extend(value.to_be_bytes());
                }
                Value::Short(value) => {
                    bytes.extend(value.to_be_bytes());
                }
                Value::String(value) => {
                    bytes.extend((value.len() as u16).to_be_bytes());
                    bytes.extend(value.clone().bytes());
                }
            },
        }
    }

    bytes
}

pub struct DSLStack {
    inner: Vec<Value>,
}

// TODO: Proper error handling
impl DSLStack {
    fn new() -> Self {
        DSLStack { inner: Vec::new() }
    }

    pub fn push(&mut self, val: Value) {
        self.inner.push(val);
    }

    pub fn pop(&mut self) -> Result<Value, ()> {
        if let Some(val) = self.inner.pop() {
            Ok(val)
        } else {
            println!("Attempted to pop an empty stack");
            Err(())
        }
    }

    pub fn pop_int(&mut self) -> Result<i64, ()> {
        match self.pop()? {
            Value::Int(i) => Ok(i),
            other => {
                println!("Attempted to pop an int but got {:?}", other);
                Err(())
            },
        }
    }

    pub fn pop_short(&mut self) -> Result<i16, ()> {
        match self.pop()? {
            Value::Short(i) => Ok(i),
            other => {
                println!("Attempted to pop a short but got {:?}", other);
                Err(())
            },
        }
    }

    pub fn pop_bool(&mut self) -> Result<bool, ()> {
        match self.pop()? {
            Value::Boolean(b) => Ok(b),
            other => {
                println!("Attempted to pop a bool but got {:?}", other);
                Err(())
            },
        }
    }

    pub fn pop_string(&mut self) -> Result<String, ()> {
        match self.pop()? {
            Value::String(s) => Ok(s),
            other => {
                println!("Attempted to pop a string but got {:?}", other);
                Err(())
            },
        }
    }
}

fn handle_op(op: OPCode, stack: &mut DSLStack) -> Result<(), ()> {
    match op {
        OPCode::LoadConstBoolTrue => {
            stack.push(Value::Boolean(true));
            Ok(())
        }
        OPCode::LoadConstBoolFalse => {
            stack.push(Value::Boolean(false));
            Ok(())
        }
        OPCode::Add => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Int(a + b));
            Ok(())
        }
        OPCode::Mul => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Int(a * b));
            Ok(())
        }
        OPCode::Div => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Int(a / b));
            Ok(())
        }
        OPCode::CmpEq => {
            let b = stack.pop()?;
            let a = stack.pop()?;
            stack.push(Value::Boolean(a == b));
            Ok(())
        }
        OPCode::Exp => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Int(a.pow(b as u32)));
            Ok(())
        }
        OPCode::CmpNeq => {
            let b = stack.pop()?;
            let a = stack.pop()?;
            stack.push(Value::Boolean(a != b));
            Ok(())
        }
        OPCode::CmpGt => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Boolean(a > b));
            Ok(())
        }
        OPCode::CmpGtEq => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Boolean(a >= b));
            Ok(())
        }
        OPCode::CmpLt => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Boolean(a < b));
            Ok(())
        }
        OPCode::CmpLtEq => {
            let b = stack.pop_int()?;
            let a = stack.pop_int()?;
            stack.push(Value::Boolean(a <= b));
            Ok(())
        }
        OPCode::RegEq => {
            let b = stack.pop_string()?;
            let a = stack.pop_string()?;
            let matched = Regex::new(&b).map_err(|_| ())?.is_match(&a);
            stack.push(Value::Boolean(matched));
            Ok(())
        }
        OPCode::RegNeq => {
            let b = stack.pop_string()?;
            let a = stack.pop_string()?;
            let matched = Regex::new(&b).map_err(|_| ())?.is_match(&a);
            stack.push(Value::Boolean(!matched));
            Ok(())
        }
        OPCode::And => {
            let b = stack.pop_bool()?;
            let a = stack.pop_bool()?;
            stack.push(Value::Boolean(a && b));
            Ok(())
        }
        OPCode::Or => {
            let b = stack.pop_bool()?;
            let a = stack.pop_bool()?;
            stack.push(Value::Boolean(a || b));
            Ok(())
        }
        OPCode::Invert => {
            let val = stack.pop()?;
            match val {
                Value::Int(i) => {
                    stack.push(Value::Int(-i));
                    Ok(())
                }
                Value::Boolean(b) => {
                    stack.push(Value::Boolean(!b));
                    Ok(())
                }
                _ => Err(()),
            }
        }
        OPCode::In => {
            let len = stack.pop_short()?;
            let mut haystack = Vec::new();
            for _ in 0..len {
                haystack.push(stack.pop()?);
            }
            let needle = stack.pop()?;
            stack.push(Value::Boolean(haystack.contains(&needle)));

            Ok(())
        }
        _ => panic!("TODO: implement OP {:?}", op),
    }
}

fn execute_bytecode<F>(
    compiled: &CompiledExpression,
    variables: HashMap<String, Value>,
    functions: HashMap<String, F>,
) -> Result<Value, ()>
where
    F: Fn(&mut DSLStack) -> Result<(), ()>,
{
    let mut stack = DSLStack::new();
    let bytecode = &compiled.0;

    let mut ptr = 0;
    while ptr < bytecode.len() {
        match &bytecode[ptr] {
            Bytecode::Instr(OPCode::CallFunc) => {
                ptr += 1;
                if let Bytecode::Value(Value::String(key)) = &bytecode[ptr] {
                    if !functions.contains_key(key) {
                        println!("Variable not found: {:?}", key);
                        return Err(());
                    }
                    functions.get(key).unwrap()(&mut stack)?;
                } else {
                    println!("LoadVar called with invalid argument: {:?}", &bytecode[ptr]);
                    return Err(());
                }
            }
            Bytecode::Instr(OPCode::LoadVar) => {
                ptr += 1;
                if let Bytecode::Value(Value::String(key)) = &bytecode[ptr] {
                    if !variables.contains_key(key) {
                        println!("Variable not found: {:?}", key);
                        return Err(());
                    }
                    stack.push(variables.get(key).unwrap().clone());
                } else {
                    println!("LoadVar called with invalid argument: {:?}", &bytecode[ptr]);
                    return Err(());
                }
            }
            Bytecode::Instr(OPCode::LoadConstInt) => {
                ptr += 1;
                if let Bytecode::Value(Value::Int(val)) = &bytecode[ptr] {
                    stack.push(Value::Int(*val));
                } else {
                    println!(
                        "LoadConstInt called with invalid argument: {:?}",
                        &bytecode[ptr]
                    );
                    return Err(());
                }
            }
            Bytecode::Instr(OPCode::LoadConstShort) => {
                ptr += 1;
                if let Bytecode::Value(Value::Short(val)) = &bytecode[ptr] {
                    stack.push(Value::Short(*val));
                } else {
                    println!(
                        "LoadConstInt called with invalid argument: {:?}",
                        &bytecode[ptr]
                    );
                    return Err(());
                }
            }
            Bytecode::Instr(OPCode::ShortJump) => {
                ptr += 1;
                let should_jump = stack.pop_bool()?;
                if should_jump {
                    if let Bytecode::Value(Value::Short(val)) = &bytecode[ptr] {
                        ptr = (ptr as isize + *val as isize) as usize;
                    } else {
                        println!(
                            "ShortJump called with invalid argument: {:?}",
                            &bytecode[ptr]
                        );
                        return Err(());
                    }
                }
            }
            Bytecode::Instr(OPCode::LoadConstStr) => {
                ptr += 1;
                if let Bytecode::Value(Value::String(val)) = &bytecode[ptr] {
                    stack.push(Value::String(val.clone()));
                } else {
                    println!(
                        "LoadConstStr called with invalid argument: {:?}",
                        &bytecode[ptr]
                    );
                    return Err(());
                }
            }
            Bytecode::Instr(op) => {
                let res = handle_op(*op, &mut stack);
                if res.is_err() {
                    return Err(res.unwrap_err());
                }
            }
            Bytecode::Value(_) => {
                println!("Unexpected value while executing bytecode");
                return Err(());
            }
        }
        ptr += 1;
    }

    stack.pop()
}

impl CompiledExpression {
    pub fn execute<F>(
        &self,
        variables: HashMap<String, Value>,
        functions: HashMap<String, F>,
    ) -> Result<Value, ()>
    where
        F: Fn(&mut DSLStack) -> Result<(), ()>,
    {
        execute_bytecode(self, variables, functions)
    }
}
