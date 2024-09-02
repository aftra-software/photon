use std::io::BufReader;

enum OPCode {
    LoadVar = 1,
    StoreVar = 2,
    LoadConstStr = 3,
    LoadConstInt = 4,   // 64 bit
    LoadConstFloat = 5, // 32 bit
    CmpGt = 6,
    CmpGtEq = 7,
    CmpEq = 8,
    CmpLtEq = 9,
    CmpLt = 10,
}

#[derive(PartialEq, Eq, Debug)]
enum TokenType {
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

#[derive(Debug)]
pub enum ParsingError {
    UnclosedString,
    UnclosedParameterBracket,
    InvalidHex,
    InvalidDigit,
    UnexpectedEOS,
    MismatchedParenthesis,
    UnknownSymbol(String)
}

#[derive(Debug)]
enum TokenValue {
    String(String),
    Char(char),
    Int(i64),
    Float(f32),
    Boolean(bool),
}

#[derive(Debug)]
pub struct Token {
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

pub fn parse_tokens(input: String, known_functions: Vec<String>) -> Result<Vec<Token>, ParsingError> {
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
        F: Fn(&char) -> bool
    {
        // TODO: Handle backspaces for escaping chars
        // When backspace is reached, read the letter after backspace and ignore condition
        let mut str = String::new();

        let mut chr = self.advance();
        loop {
            if chr.is_none() {
                return (str, false);
            }
            if !condition(&chr.unwrap()) {
                self.rewind(1); // This character did not fulfil condition, so we step back
                break;
            }
            str.push(chr.unwrap());
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
                            let hex_value = i64::from_str_radix(&hex_str, 16).map_err(|_| ParsingError::InvalidHex)?;
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
                let number = token_str.parse::<i64>().map_err(|_| ParsingError::InvalidDigit)?;

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
                    value: TokenValue::String(token_str)
                })
            }

            self.rewind(1);
            let (token_str, _) = self.read_while(|chr| !chr.is_alphanumeric() && !chr.is_whitespace());

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
                        value: TokenValue::String(token_str),
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
                        value: TokenValue::String(token_str),
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
