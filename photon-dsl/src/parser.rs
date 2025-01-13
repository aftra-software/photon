use pest::{
    iterators::{Pair, Pairs},
    pratt_parser::PrattParser,
    Parser,
};
use pest_derive::Parser;

use crate::{
    dsl::{compile_bytecode, optimize_expr, CompiledExpression, Expr, Operator, Value},
    get_config,
};

#[derive(Parser)]
#[grammar = "dsl.pest"]
pub struct DSLParser;

pub fn compile_expression(data: &str) -> Result<CompiledExpression, ()> {
    Ok(compile_bytecode(do_parsing(data)?))
}

pub fn do_parsing(data: &str) -> Result<Expr, ()> {
    let res = DSLParser::parse(Rule::init, data);
    if let Err(err) = &res {
        debug!("parser error: {:?}", err);
    }
    let expr = parse_expr(res.map_err(|_| ())?);
    Ok(optimize_expr(expr))
}

lazy_static::lazy_static! {
    static ref PRATT_PARSER: PrattParser<Rule> = {
        use pest::pratt_parser::{Assoc::Left, Op};
        use Rule::*;

        // Precedence is defined lowest to highest
        PrattParser::new()
            // Addition and subtract have equal precedence
            .op(Op::infix(or, Left))
            .op(Op::infix(and, Left))
            .op(Op::infix(bitor, Left))
            .op(Op::infix(xor, Left))
            .op(Op::infix(bitand, Left))
            .op(Op::infix(eq, Left)
                | Op::infix(neq, Left)
                | Op::infix(regexeq, Left)
                | Op::infix(regexneq, Left))
            .op(Op::infix(gt, Left)
                | Op::infix(gteq, Left)
                | Op::infix(lt, Left)
                | Op::infix(lteq, Left))
            .op(Op::infix(shl, Left) | Op::infix(shr, Left))
            .op(Op::infix(add, Left) | Op::infix(sub, Left))
            .op(Op::infix(mul, Left) | Op::infix(div, Left) | Op::infix(r#mod, Left))
            .op(Op::infix(r#in, Left))
            .op(Op::infix(exp, Left))
            .op(Op::prefix(not) | Op::prefix(neg) | Op::prefix(bitnot))
    };
}

fn unescape(s: &str) -> Result<String, ()> {
    let mut ins = s.chars();
    let mut out = String::with_capacity(s.len());

    while let Some(c) = ins.next() {
        if c == '\\' {
            match ins.next() {
                None => {
                    return Err(());
                }
                Some(d) => {
                    out.push(d);
                }
            }
        } else {
            out.push(c);
        }
    }

    Ok(out)
}

fn parse_primary(primary: Pair<'_, Rule>) -> Expr {
    match primary.as_rule() {
        Rule::expr | Rule::clause => parse_expr(primary.into_inner()),
        Rule::string => Expr::Constant(Value::String(unescape(primary.as_str()).unwrap())),
        Rule::boolean => Expr::Constant(Value::Boolean(primary.as_str().parse::<bool>().unwrap())),
        Rule::variable => Expr::Variable(primary.as_str().to_string()),
        Rule::digit => {
            let num = primary.as_str();
            if let Some(stripped) = num.strip_prefix("0x") {
                Expr::Constant(Value::Int(i64::from_str_radix(stripped, 16).unwrap()))
            } else {
                Expr::Constant(Value::Int(num.parse::<i64>().unwrap()))
            }
        }
        Rule::list => Expr::List(
            primary
                .into_inner()
                .map(|pair| parse_primary(pair))
                .collect(),
        ),
        Rule::ternary => {
            let mut inner = primary.into_inner();
            let left = parse_primary(inner.next().unwrap());
            let middle = parse_primary(inner.next().unwrap());
            let right = parse_primary(inner.next().unwrap());
            Expr::Ternary(Box::new(left), Box::new(middle), Box::new(right))
        }
        Rule::function => {
            let mut iter = primary.into_inner();
            let func = iter.next().unwrap().as_str();
            let arg_pairs = iter.next().unwrap();
            let args = arg_pairs
                .into_inner()
                .map(|pair| parse_primary(pair))
                .collect();

            Expr::Function(func.to_string(), args)
        }
        rule => unreachable!("Expr::parse expected atom, found {:?}", rule),
    }
}

fn parse_expr(pairs: Pairs<Rule>) -> Expr {
    PRATT_PARSER
        .map_primary(parse_primary)
        .map_infix(|lhs, op, rhs| {
            let op = match op.as_rule() {
                Rule::and => Operator::And,
                Rule::or => Operator::Or,
                Rule::r#in => Operator::In,
                Rule::exp => Operator::Exp,
                Rule::shl => Operator::Shl,
                Rule::shr => Operator::Shr,
                Rule::add => Operator::Add,
                Rule::sub => Operator::Sub,
                Rule::mul => Operator::Mul,
                Rule::r#mod => Operator::Mod,
                Rule::div => Operator::Div,
                Rule::neq => Operator::Neq,
                Rule::eq => Operator::Eq,
                Rule::gt => Operator::Gt,
                Rule::gteq => Operator::GtEq,
                Rule::lt => Operator::Lt,
                Rule::lteq => Operator::LtEq,
                Rule::regexeq => Operator::RegexEq,
                Rule::regexneq => Operator::RegexNeq,
                Rule::xor => Operator::Xor,
                Rule::bitand => Operator::BitAnd,
                Rule::bitor => Operator::BitOr,
                rule => unreachable!("Expr::parse expected infix operation, found {:?}", rule),
            };
            Expr::Operator(Box::new(lhs), op, Box::new(rhs))
        })
        .map_prefix(|op, rhs| match op.as_rule() {
            Rule::not | Rule::neg => Expr::Prefix(Operator::Invert, Box::new(rhs)),
            Rule::bitnot => Expr::Prefix(Operator::BitwiseNot, Box::new(rhs)),
            rule => unreachable!("Expr::parse expected infix operation, found {:?}", rule),
        })
        .parse(pairs)
}
