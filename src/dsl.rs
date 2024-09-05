use core::panic;
use std::collections::HashMap;

use regex::Regex;

#[derive(Debug, Copy, Clone)]
pub enum OPCode {
    // Basic Operators
    LoadVar = 1,
    StoreVar = 2,
    LoadConstStr = 3,
    LoadConstInt = 4,   // 64 bit
    LoadConstFloat = 5, // 32 bit
    LoadConstBool = 6,
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
    ListContains = 32, // TODO: implement
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    String(String),
    Int(i64),
    Boolean(bool),
}

#[derive(Debug)]
pub enum Bytecode {
    Instr(OPCode),
    Value(Value),
}

#[derive(Debug)]
pub struct CompiledExpression(Vec<Bytecode>);

#[derive(PartialEq, Eq, Debug)]
pub(crate) enum Token {
    Operator(Operator),
    Numeric(i64), // TODO: support int and float?
    Boolean(bool),
    Variable(String),
    String(String),
    Function(String),
    Clause,
    ClauseClose,
    Prefix(char),
    Seperator(char), // Seperator between elements in a list (1, 2, 3)
    Ternary(String),
    Unknown,
}

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
    BinaryAnd,
    BinaryOr,
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

fn map_logical_op(op: &str) -> Operator {
    match op {
        "&&" => Operator::And,
        "||" => Operator::Or,
        _ => panic!("Should be impossible??"),
    }
}

fn map_comparator_op(op: &str) -> Operator {
    match op {
        "==" => Operator::Eq,
        ">=" => Operator::GtEq,
        ">" => Operator::Gt,
        "<=" => Operator::LtEq,
        "<" => Operator::Lt,
        "!=" => Operator::Neq,
        "=~" => Operator::RegexEq,
        "!~" => Operator::RegexNeq,
        "in" => Operator::In,
        _ => panic!("Should be impossible??"),
    }
}

fn map_binary_op(op: &str) -> Operator {
    match op {
        "+" => Operator::Add,
        "-" => Operator::Sub,
        "*" => Operator::Mul,
        "/" => Operator::Div,
        "%" => Operator::Mod,
        "**" => Operator::Exp,
        "&" => Operator::BinaryAnd,
        "|" => Operator::BinaryOr,
        "^" => Operator::Xor,
        "<<" => Operator::Shl,
        ">>" => Operator::Shr,
        _ => panic!("Should be impossible??"),
    }
}

#[derive(Debug)]
pub(crate) enum ParsingError {
    UnclosedString,
    UnclosedParameterBracket,
    InvalidHex,
    InvalidDigit,
    UnexpectedEOS,
    MismatchedParenthesis,
    UnknownSymbol(String),
}

impl Token {
    fn can_transition_to(&self, token: Token) -> bool {
        // TODO: grammar allowed transitions
        true
    }
}

struct DSLParser {
    current: usize,
    buffer: String,
    known_functions: Vec<String>,
    current_state: Token,
}

fn validate_balance(tokens: &[Token]) -> bool {
    let mut open = 0;
    for token in tokens {
        if *token == Token::Clause {
            open += 1;
        } else if *token == Token::ClauseClose {
            open -= 1;
        }
    }
    open == 0
}

fn is_variable_letter(chr: &char) -> bool {
    chr.is_alphanumeric() || *chr == '_' || *chr == '.'
}

pub fn parse_tokens(
    input: String,
    known_functions: Vec<String>,
) -> Result<Vec<Token>, ParsingError> {
    let mut parser = DSLParser {
        buffer: input,
        current: 0,
        current_state: Token::Unknown,
        known_functions,
    };

    let mut tokens = Vec::new();

    while parser.can_advance() {
        let token = parser.next_token();
        if token.is_err() {
            return Err(token.unwrap_err());
        }
        tokens.push(token.unwrap());
        // TODO: get next state from token and apply to DSLParser
    }

    if !validate_balance(&tokens) {
        Err(ParsingError::MismatchedParenthesis)
    } else {
        Ok(tokens)
    }
}

impl DSLParser {
    fn rewind(&mut self, step: isize) {
        self.current = (self.current as isize - step) as usize;
    }

    fn advance(&mut self) -> Option<char> {
        self.current += 1;
        self.buffer[self.current - 1..].chars().next()
    }

    fn can_advance(&mut self) -> bool {
        self.buffer.len() > self.current
    }

    fn read_while<F>(&mut self, condition: F) -> (String, bool)
    where
        F: Fn(&char) -> bool,
    {
        let mut str = String::new();

        let mut chr = self.advance();
        loop {
            // End of stream
            if chr.is_none() {
                return (str, false);
            }

            let c = chr.unwrap();
            if c == '\\' {
                chr = self.advance(); // Skip to next character
                match chr {
                    Some(ch) => str.push(ch),
                    None => {
                        return (str, false);
                    }
                }
                chr = self.advance(); // Skip over escaped sequence and continue
                continue;
            }

            if !condition(&c) {
                self.rewind(1); // This character did not fulfil condition, so we step back
                break;
            }
            str.push(c);
            chr = self.advance();
        }

        (str, true)
    }

    fn next_token(&mut self) -> Result<Token, ParsingError> {
        while let Some(chr) = self.advance() {
            if chr.is_whitespace() {
                continue;
            }

            if chr.is_numeric() {
                if chr == '0' {
                    if let Some(next) = self.advance() {
                        if next == 'x' {
                            let (hex_str, _) = self.read_while(char::is_ascii_hexdigit);
                            let hex_value = i64::from_str_radix(&hex_str, 16)
                                .map_err(|_| ParsingError::InvalidHex)?;
                            return Ok(Token::Numeric(hex_value));
                        } else {
                            self.rewind(1); // were looking for 0x, so 2 back
                        }
                    }
                }
                self.rewind(1);

                let (token_str, _) = self.read_while(|chr| chr.is_numeric());
                let number = token_str
                    .parse::<i64>()
                    .map_err(|_| ParsingError::InvalidDigit)?;

                return Ok(Token::Numeric(number));
            }

            match chr {
                ',' => {
                    return Ok(Token::Seperator(chr));
                }
                '(' => {
                    return Ok(Token::Clause);
                }
                ')' => {
                    return Ok(Token::ClauseClose);
                }
                _ => {}
            }

            if chr == '[' {
                let (token_str, finished) = self.read_while(|chr| *chr != ']');
                if !finished {
                    return Err(ParsingError::UnclosedParameterBracket);
                }
                return Ok(Token::Variable(token_str));
            }

            if is_variable_letter(&chr) {
                self.rewind(1);
                let (token_str, _) = self.read_while(is_variable_letter);

                match token_str.as_str() {
                    "true" => {
                        return Ok(Token::Boolean(true));
                    }
                    "false" => {
                        return Ok(Token::Boolean(false));
                    }
                    "in" | "IN" => return Ok(Token::Operator(Operator::In)),
                    _ => {}
                }

                if self.known_functions.contains(&token_str) {
                    return Ok(Token::Function(token_str));
                }

                return Ok(Token::Variable(token_str));

                // TODO: Accessor? Not sure if it's needed so I'll skip for now.
            }

            if chr == '"' || chr == '\'' {
                let (token_str, finished) = self.read_while(|ch| *ch != chr);
                if !finished {
                    return Err(ParsingError::UnclosedString);
                }

                self.rewind(-1); // Step forward

                // TODO: time handling here

                return Ok(Token::String(token_str));
            }

            self.rewind(1);
            let (token_str, _) =
                self.read_while(|chr| !chr.is_alphanumeric() && !chr.is_whitespace() && *chr != '(' && *chr != ')');

            // Handle prefix case, to differentiate between prefix and cmp operation (!= vs !)
            if self
                .current_state
                .can_transition_to(Token::Prefix(token_str.chars().next().unwrap()))
            {
                match token_str.as_str() {
                    "-" | "!" | "~" => {
                        return Ok(Token::Prefix(token_str.chars().next().unwrap()));
                    }
                    _ => {}
                }
            }

            match token_str.as_str() {
                "+" | "-" | "*" | "/" | "%" | "**" | "&" | "|" | "^" | "<<" | ">>" => {
                    return Ok(Token::Operator(map_binary_op(&token_str)));
                }
                "&&" | "||" => {
                    return Ok(Token::Operator(map_logical_op(&token_str)));
                }
                "==" | ">=" | ">" | "<=" | "<" | "!=" | "=~" | "!~" | "in" => {
                    return Ok(Token::Operator(map_comparator_op(&token_str)));
                }
                "?" | ":" | "??" => {
                    return Ok(Token::Ternary(token_str));
                }
                _ => {
                    return Err(ParsingError::UnknownSymbol(token_str));
                }
            }
        }
        Err(ParsingError::UnexpectedEOS)
    }
}

#[derive(Debug)]
pub enum Expr {
    Operator(Box<Expr>, Operator, Box<Expr>),
    Function(String, Vec<Expr>),
    Constant(Value),
    Variable(String),
    Prefix(Operator, Box<Expr>),
}
struct TokenStream<'a> {
    tokens: &'a [Token],
    position: usize,
}

impl<'a> TokenStream<'a> {
    fn advance(&mut self) {
        self.position += 1;
    }

    fn current(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }
}

fn get_precedence(op: &Operator) -> u8 {
    match op {
        Operator::Or => 1,
        Operator::And => 2,
        Operator::BinaryOr => 3,
        Operator::Xor => 4,
        Operator::BinaryAnd => 5,
        Operator::Eq | Operator::Neq | Operator::RegexEq | Operator::RegexNeq => 6,
        Operator::Gt | Operator::GtEq | Operator::Lt | Operator::LtEq => 7,
        Operator::Shl | Operator::Shr => 8,
        Operator::Add | Operator::Sub => 9,
        Operator::Mul | Operator::Div | Operator::Mod => 10,
        Operator::Exp => 11,
        Operator::Invert | Operator::BitwiseNot => 12, // ! and - prefixes
        Operator::In => 13,
    }
}

fn peek_operator(tokens: &TokenStream) -> Option<Operator> {
    if let Some(Token::Operator(op)) = tokens.current() {
        Some(op.clone())
    } else {
        None
    }
}

pub fn parse_expr(tokens: &[Token]) -> Expr {
    optimize_expr(parse_expression(
        &mut TokenStream {
            tokens,
            position: 0,
        },
        0,
    ))
}

fn parse_expression(tokens: &mut TokenStream, min_precedence: u8) -> Expr {
    let mut left = parse_primary(tokens);

    while let Some(op) = peek_operator(tokens) {
        let precedence = get_precedence(&op);
        if precedence < min_precedence {
            break;
        }

        tokens.advance(); // Consume the operator
        let next_min_precedence = precedence + 1;

        let right = parse_expression(tokens, next_min_precedence);

        left = Expr::Operator(Box::new(left), op, Box::new(right));
    }

    left
}

fn parse_primary(tokens: &mut TokenStream) -> Expr {
    match tokens.current() {
        Some(Token::Clause) => {
            tokens.advance();
            let expr = parse_expression(tokens, 0);

            if let Some(Token::ClauseClose) = tokens.current() {
                tokens.advance();
            } else {
                panic!("Expected closing parenthesis");
            }

            expr
        }
        Some(Token::Prefix(prefix)) => {
            let op = match prefix {
                '-' | '!' => Operator::Invert,
                '~' => Operator::BitwiseNot,
                _ => panic!("Impossible, got prefix {}, shouldn't be possible to have parsed that as a token", prefix)
            };
            tokens.advance();
            let expr = parse_expression(tokens, 0);
            println!("hi");
            Expr::Prefix(op, Box::new(expr))
        }
        Some(Token::Boolean(value)) => {
            let expr = Expr::Constant(Value::Boolean(*value));
            tokens.advance();
            expr
        }
        Some(Token::Numeric(value)) => {
            let expr = Expr::Constant(Value::Int(*value));
            tokens.advance();
            expr
        }
        Some(Token::String(value)) => {
            let expr = Expr::Constant(Value::String(value.clone()));
            tokens.advance();
            expr
        }
        Some(Token::Variable(value)) => {
            let expr = Expr::Variable(value.clone());
            tokens.advance();
            expr
        }
        Some(Token::Function(func_name)) => {
            let name = func_name.clone();
            tokens.advance();
            if let Some(Token::Clause) = tokens.current() {
                tokens.advance(); // Consume the '('

                let mut args = Vec::new();

                if let Some(Token::ClauseClose) = tokens.current() {
                    tokens.advance();
                } else {
                    loop {
                        args.push(parse_expression(tokens, 0));

                        match tokens.current() {
                            Some(Token::Seperator(_)) => {
                                tokens.advance();
                            }
                            Some(Token::ClauseClose) => {
                                tokens.advance();
                                break;
                            }
                            _ => panic!("Expected ',' or ')' after function argument"),
                        }
                    }
                }

                Expr::Function(name, args)
            } else {
                panic!("Expected opening parenthesis after function name");
            }
        }
        _ => panic!("unexpected token"),
    }
}

fn optimize_expr(expr: Expr) -> Expr {
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
                if let Expr::Constant(Value::Boolean(r_b)) = optimized_right {
                    if r_b {
                        return Expr::Constant(Value::Boolean(true));
                    }
                }
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
        Expr::Function(name, args) => Expr::Function(
            name,
            args.into_iter().map(|arg| optimize_expr(arg)).collect(),
        ),

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
        Operator::BinaryAnd => OPCode::BinAnd,
        Operator::BinaryOr => OPCode::BinOr,
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
        Expr::Constant(value) => {
            let op = match value {
                Value::Boolean(_) => OPCode::LoadConstBool,
                Value::String(_) => OPCode::LoadConstStr,
                Value::Int(_) => OPCode::LoadConstInt,
            };
            CompiledExpression(vec![Bytecode::Instr(op), Bytecode::Value(value)])
        }
        Expr::Prefix(op, expr) => {
            let mut ops = Vec::new();
            ops.append(&mut compile_bytecode(*expr).0);
            ops.push(Bytecode::Instr(map_op(op)));

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
            Err(())
        }
    }

    pub fn pop_int(&mut self) -> Result<i64, ()> {
        match self.pop()? {
            Value::Int(i) => Ok(i),
            _ => Err(()),
        }
    }

    pub fn pop_bool(&mut self) -> Result<bool, ()> {
        match self.pop()? {
            Value::Boolean(b) => Ok(b),
            _ => Err(()),
        }
    }

    pub fn pop_string(&mut self) -> Result<String, ()> {
        match self.pop()? {
            Value::String(s) => Ok(s),
            _ => Err(()),
        }
    }
}

fn handle_op(op: OPCode, stack: &mut DSLStack) -> Result<(), ()> {
    match op {
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
            Bytecode::Instr(OPCode::LoadConstBool) => {
                ptr += 1;
                if let Bytecode::Value(Value::Boolean(val)) = &bytecode[ptr] {
                    stack.push(Value::Boolean(*val));
                } else {
                    println!(
                        "LoadConstBool called with invalid argument: {:?}",
                        &bytecode[ptr]
                    );
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
