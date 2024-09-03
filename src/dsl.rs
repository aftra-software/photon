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

#[derive(PartialEq, Eq, Debug)]
pub(crate) enum TokenType {
    Comparator,
    Numeric,
    Boolean,
    Variable,
    String,
    Function,
    Clause,
    ClauseClose,
    Prefix,
    Modifier,
    Seperator, // Seperator between elements in a list (1, 2, 3)
    LogicalOp, // || && etc
    BinaryOp,  // ! ~ + - * etc
    Ternary,
    Unknown,
}

#[derive(Debug, Clone)]
enum ComparatorOp {
    Eq,
    Neq,
    Gt,
    GtEq,
    Lt,
    LtEq,
    RegexEq,
    RegexNeq,
    In,
}

fn map_comparator_op(op: &str) -> ComparatorOp {
    match op {
        "==" => ComparatorOp::Eq,
        ">=" => ComparatorOp::GtEq,
        ">" => ComparatorOp::Gt,
        "<=" => ComparatorOp::LtEq,
        "<" => ComparatorOp::Lt,
        "!=" => ComparatorOp::Neq,
        "=~" => ComparatorOp::RegexEq,
        "!~" => ComparatorOp::RegexNeq,
        "in" => ComparatorOp::In,
        _ => panic!("Should be impossible??"),
    }
}

#[derive(Debug, Clone)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Exp,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

fn map_binary_op(op: &str) -> BinaryOp {
    match op {
        "+" => BinaryOp::Add,
        "-" => BinaryOp::Sub,
        "*" => BinaryOp::Mul,
        "/" => BinaryOp::Div,
        "%" => BinaryOp::Mod,
        "**" => BinaryOp::Exp,
        "&" => BinaryOp::And,
        "|" => BinaryOp::Or,
        "^" => BinaryOp::Xor,
        "<<" => BinaryOp::Shl,
        ">>" => BinaryOp::Shr,
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

#[derive(Debug)]
pub(crate) enum TokenValue {
    String(String),
    Char(char),
    Int(i64),
    Float(f32),
    Boolean(bool),
    BinaryOp(BinaryOp),
    ComparatorOp(ComparatorOp),
}

#[derive(Debug)]
pub(crate) struct Token {
    pub kind: TokenType,
    pub value: TokenValue,
}

impl TokenType {
    fn can_transition_to(&self, token: TokenType) -> bool {
        // TODO: grammar allowed transitions
        return false;
    }
}

struct DSLParser {
    current: usize,
    buffer: String,
    known_functions: Vec<String>,
    current_state: TokenType,
}

fn validate_balance(tokens: &[Token]) -> bool {
    let mut open = 0;
    for token in tokens {
        if token.kind == TokenType::Clause {
            open += 1;
        } else if token.kind == TokenType::ClauseClose {
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
        current_state: TokenType::Unknown,
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
                            return Ok(Token {
                                kind: TokenType::Numeric,
                                value: TokenValue::Int(hex_value),
                            });
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

                return Ok(Token {
                    kind: TokenType::Numeric,
                    value: TokenValue::Int(number),
                });
            }

            match chr {
                ',' => {
                    return Ok(Token {
                        kind: TokenType::Seperator,
                        value: TokenValue::Char(chr),
                    });
                }
                '(' => {
                    return Ok(Token {
                        kind: TokenType::Clause,
                        value: TokenValue::Char(chr),
                    });
                }
                ')' => {
                    return Ok(Token {
                        kind: TokenType::ClauseClose,
                        value: TokenValue::Char(chr),
                    });
                }
                _ => {}
            }

            if chr == '[' {
                let (token_str, finished) = self.read_while(|chr| *chr != ']');
                if !finished {
                    return Err(ParsingError::UnclosedParameterBracket);
                }
                return Ok(Token {
                    kind: TokenType::Variable,
                    value: TokenValue::String(token_str),
                });
            }

            if is_variable_letter(&chr) {
                self.rewind(1);
                let (token_str, _) = self.read_while(is_variable_letter);

                match token_str.as_str() {
                    "true" => {
                        return Ok(Token {
                            kind: TokenType::Boolean,
                            value: TokenValue::Boolean(true),
                        });
                    }
                    "false" => {
                        return Ok(Token {
                            kind: TokenType::Boolean,
                            value: TokenValue::Boolean(false),
                        });
                    }
                    "in" | "IN" => {
                        return Ok(Token {
                            kind: TokenType::Comparator,
                            value: TokenValue::String("in".into()),
                        })
                    }
                    _ => {}
                }

                if self.known_functions.contains(&token_str) {
                    return Ok(Token {
                        kind: TokenType::Function,
                        value: TokenValue::String(token_str),
                    });
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

                return Ok(Token {
                    kind: TokenType::String,
                    value: TokenValue::String(token_str),
                });
            }

            self.rewind(1);
            let (token_str, _) =
                self.read_while(|chr| !chr.is_alphanumeric() && !chr.is_whitespace());

            // Handle prefix case, to differentiate between prefix and boolean operation
            if self.current_state.can_transition_to(TokenType::Prefix) {
                match token_str.as_str() {
                    "-" | "!" | "~" => {
                        return Ok(Token {
                            kind: TokenType::Prefix,
                            value: TokenValue::String(token_str),
                        })
                    }
                    _ => {}
                }
            }

            match token_str.as_str() {
                "+" | "-" | "*" | "/" | "%" | "**" | "&" | "|" | "^" | "<<" | ">>" => {
                    return Ok(Token {
                        kind: TokenType::Modifier,
                        value: TokenValue::BinaryOp(map_binary_op(&token_str)),
                    })
                }
                "&&" | "||" => {
                    return Ok(Token {
                        kind: TokenType::LogicalOp,
                        value: TokenValue::String(token_str),
                    })
                }
                "==" | ">=" | ">" | "<=" | "<" | "!=" | "=~" | "!~" | "in" => {
                    return Ok(Token {
                        kind: TokenType::Comparator,
                        value: TokenValue::ComparatorOp(map_comparator_op(&token_str)),
                    })
                }
                "?" | ":" | "??" => {
                    return Ok(Token {
                        kind: TokenType::Ternary,
                        value: TokenValue::String(token_str),
                    })
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
pub enum ASTNode {
    Compare {
        op: ComparatorOp,
        left: Box<ASTNode>,
        right: Box<ASTNode>,
    },
    Function {
        name: String,
        parameters: Vec<ASTNode>,
    },
    Constant {
        value: TokenValue,
    },
    Variable {
        name: String,
    },
    BinaryOperator {
        op: BinaryOp,
        left: Box<ASTNode>,
        right: Box<ASTNode>,
    },
}

fn match_clause(tokens: &[Token]) -> usize {
    // Skip first one, we know its the opening clause
    let mut counter = 1;
    for (idx, token) in tokens.iter().skip(1).enumerate() {
        println!("counter: {counter}");
        if token.kind == TokenType::Clause {
            counter += 1;
        } else if token.kind == TokenType::ClauseClose {
            counter -= 1;
        }
        if counter == 0 {
            return idx + 1;
        }
    }
    println!("{counter}");
    panic!("Could not find clause, fix!!!")
}

pub fn build_ast(tokens: &[Token]) -> ASTNode {
    // Handle e.g. (5 > 4)
    let mut left = None;
    let mut cur_idx = 0;

    if tokens[cur_idx].kind == TokenType::Clause {
        println!("hi");
        let clause_end = match_clause(tokens);
        println!("matched clause: {:?}", &tokens[cur_idx..clause_end]);
        left = Some(build_ast(&tokens[cur_idx + 1..clause_end]));
        cur_idx = clause_end + 1;
        if cur_idx == tokens.len() {
            return left.unwrap();
        }
    } else if tokens[cur_idx].kind == TokenType::Function {
        if tokens[cur_idx + 1].kind != TokenType::Clause {
            panic!("function but no parenthesis");
        }

        let mut splits = vec![cur_idx + 1];
        let clause_end = match_clause(&tokens[cur_idx + 1..]);
        println!("cur: {:?}", tokens[cur_idx]);
        println!("matched: {:?}", &tokens[cur_idx + 1..clause_end + 1]);
        let mut opens = 0; // Used to make sure we don't split on an inner parameter deeper in the tree
        for tok_idx in (cur_idx + 1)..clause_end {
            if tokens[tok_idx].kind == TokenType::Clause {
                opens += 1;
            } else if tokens[tok_idx].kind == TokenType::ClauseClose {
                opens -= 1;
            } else if opens == 0 && tokens[tok_idx].kind == TokenType::Seperator {
                splits.push(tok_idx);
            }
        }
        splits.push(clause_end - 1);

        let params = splits
            .windows(2)
            .map(|positions| build_ast(&tokens[positions[0]..positions[1] + 1]))
            .collect();

        let func_name = match &tokens[cur_idx].value {
            TokenValue::String(name) => name.clone(),
            _ => panic!("function has no name?"),
        };

        return ASTNode::Function {
            name: func_name,
            parameters: params,
        };
    }

    if tokens[cur_idx].kind == TokenType::BinaryOp {
        if left.is_none() {
            panic!("fuck, left is none but we're doing an operation??? wtf");
        }

        let right = build_ast(&tokens[cur_idx + 1..]);
        let op = match &tokens[cur_idx].value {
            TokenValue::BinaryOp(op) => op.clone(),
            _ => panic!("impossible"),
        };
        return ASTNode::BinaryOperator {
            op,
            left: Box::new(left.unwrap()),
            right: Box::new(right),
        };
    }

    ASTNode::Constant {
        value: TokenValue::String("We don fucked up".into()),
    }
}
