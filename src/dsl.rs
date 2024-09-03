use core::panic;

enum OPCode {
    // Basic Operators
    LoadVar = 1,
    StoreVar = 2,
    LoadConstStr = 3,
    LoadConstInt = 4,   // 64 bit
    LoadConstFloat = 5, // 32 bit
    CallFunc = 6,

    // Comparison Operators
    CmpGt = 7,
    CmpGtEq = 8,
    CmpEq = 9,
    CmpNeq = 10,
    CmpLtEq = 11,
    CmpLt = 12,

    // Binary Operators
    Add = 13,
    Sub = 14,
    Mul = 15,
    Div = 16,
}

#[derive(Debug, Clone)]
pub(crate) enum TokenValue {
    String(String),
    Char(char),
    Int(i64),
    Float(f32),
    Boolean(bool),
    Operator(Operator),
}

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
    Modifier(String),
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
    Or
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
        return false;
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
                    "in" | "IN" => {
                        return Ok(Token::Operator(Operator::In))
                    }
                    _ => {}
                }

                if self.known_functions.contains(&token_str) {
                    return Ok(Token::Function(token_str));
                }

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
                self.read_while(|chr| !chr.is_alphanumeric() && !chr.is_whitespace());

            // Handle prefix case, to differentiate between prefix and boolean operation
            if self.current_state.can_transition_to(Token::Prefix(token_str.chars().next().unwrap())) {
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
    Constant(TokenValue),
    Variable(String),
}
struct TokenStream<'a> {
    tokens: &'a [Token],
    position: usize,
}

impl<'a> TokenStream<'a> {
    fn advance(&mut self) {
        println!("eated: {:?}", self.tokens[self.position]);
        self.position += 1;
    }

    fn current(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }
}


fn match_clause(tokens: &[Token]) -> usize {
    // Skip first one, we know its the opening clause
    let mut counter = 1;
    for (idx, token) in tokens.iter().skip(1).enumerate() {
        if *token == Token::Clause {
            counter += 1;
        } else if *token == Token::ClauseClose {
            counter -= 1;
        }
        if counter == 0 {
            return idx + 1;
        }
    }
    panic!("Could not find clause, fix!!!")
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
        Operator::In => 12
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
    parse_expression(&mut TokenStream { tokens, position: 0 }, 0)
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
        },
        Some(Token::Boolean(value)) => {
            let expr = Expr::Constant(TokenValue::Boolean(*value));
            tokens.advance();
            expr
        },
        Some(Token::Numeric(value)) => {
            let expr = Expr::Constant(TokenValue::Int(*value));
            tokens.advance();
            expr
        },
        Some(Token::String(value)) => {
            let expr = Expr::Constant(TokenValue::String(value.clone()));
            tokens.advance();
            expr
        },
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
        },
        _ => panic!("unexpected token")
    }
}