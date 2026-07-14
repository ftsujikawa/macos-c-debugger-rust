use std::io;

use crate::register::ThreadState64;

#[derive(Debug, Clone)]
enum Token {
    Number(u64),
    Register(String),
    Ident(String),
    Plus,
    Minus,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Not,
    Dot,     // .
    Arrow,   // ->
    LParen,
    RParen,
    End,
}

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Not,
    Neg,
    Deref,
    AddrOf,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Number(u64),
    Register(String),
    Variable(String),
    Unary(Op, Box<Expr>),
    Binary(Op, Box<Expr>, Box<Expr>),
    /// expr.field
    Member(Box<Expr>, String),
    /// expr->field  (pointer member access)
    PtrMember(Box<Expr>, String),
}

/// 式の評価に必要なコンテキストを保持します。
pub struct EvalContext<'a> {
    pub regs: &'a ThreadState64,
    pub base: Option<u64>,
    pub read_mem: Option<&'a dyn Fn(usize, usize) -> io::Result<Vec<u8>>>,
    /// 変数名を (アドレス, バイト数, type_name, is_pointer, pointee_type) に解決するコールバック
    pub resolve_var: Option<&'a dyn Fn(&str) -> Result<(u64, u8), String>>,
    /// 変数のアドレスのみを返すコールバック (&演算子用)
    pub addr_of_var: Option<&'a dyn Fn(&str) -> Result<u64, String>>,
    /// struct 型名とフィールド名から (offset, size) を返すコールバック
    pub resolve_field: Option<&'a dyn Fn(&str, &str) -> Result<(u64, u8), String>>,
    /// 変数の型名 (type_name, is_pointer, pointee_type) を返すコールバック
    pub type_of_var: Option<&'a dyn Fn(&str) -> Result<(String, bool, String), String>>,
}

impl<'a> EvalContext<'a> {
    pub fn new(
        regs: &'a ThreadState64,
        base: Option<u64>,
        read_mem: Option<&'a dyn Fn(usize, usize) -> io::Result<Vec<u8>>>,
    ) -> Self {
        Self {
            regs,
            base,
            read_mem,
            resolve_var: None,
            addr_of_var: None,
            resolve_field: None,
            type_of_var: None,
        }
    }
}

/// 文字列を式としてパースします。
pub fn parse(input: &str) -> Result<Expr, String> {
    let mut parser = Parser::new(input);
    parser.parse()
}

/// 式を評価して u64 値を返します。
pub fn eval(expr: &Expr, ctx: &EvalContext) -> Result<u64, String> {
    match expr {
        Expr::Number(v) => Ok(*v),
        Expr::Register(name) => {
            if name == "base" {
                ctx.base.ok_or_else(|| "image base unknown".to_string())
            } else {
                ctx.regs
                    .get(name)
                    .ok_or_else(|| format!("unknown register: ${}", name))
            }
        }
        Expr::Variable(name) => {
            let resolve = ctx
                .resolve_var
                .ok_or_else(|| "variable resolution not available".to_string())?;
            let (addr, size) = resolve(name)?;
            let read = ctx
                .read_mem
                .ok_or_else(|| "memory read not available".to_string())?;
            let n = (size as usize).clamp(1, 8);
            let bytes = read(addr as usize, n)
                .map_err(|e| format!("failed to read variable {}: {}", name, e))?;
            let size = n.min(bytes.len());
            if size == 0 {
                return Err(format!("failed to read variable {}", name));
            }
            let mut buf = [0u8; 8];
            buf[..size].copy_from_slice(&bytes[..size]);
            Ok(u64::from_le_bytes(buf))
        }
        Expr::Unary(op, inner) => {
            match op {
                Op::AddrOf => {
                    // & 演算子: 変数のアドレスを返す
                    match inner.as_ref() {
                        Expr::Variable(name) => {
                            let addr_of = ctx.addr_of_var.ok_or_else(|| {
                                "address-of not available".to_string()
                            })?;
                            addr_of(name)
                        }
                        _ => Err("& can only be applied to a variable name".to_string()),
                    }
                }
                _ => {
                    let v = eval(inner, ctx)?;
                    match op {
                        Op::Neg => Ok(v.wrapping_neg()),
                        Op::Not => Ok(!v),
                        Op::Deref => {
                            let read = ctx
                                .read_mem
                                .ok_or_else(|| "memory read not available for '*'".to_string())?;
                            let bytes = read(v as usize, 8)
                                .map_err(|e| format!("failed to read memory: {}", e))?;
                            if bytes.len() < 8 {
                                return Err("not enough bytes to read 64-bit value".to_string());
                            }
                            let mut buf = [0u8; 8];
                            buf.copy_from_slice(&bytes[..8]);
                            Ok(u64::from_le_bytes(buf))
                        }
                        _ => Err(format!("unsupported unary operator: {:?}", op)),
                    }
                }
            }
        }
        Expr::Binary(op, l, r) => {
            let lv = eval(l, ctx)?;
            let rv = eval(r, ctx)?;
            let res = match op {
                Op::Add => lv.wrapping_add(rv),
                Op::Sub => lv.wrapping_sub(rv),
                Op::Mul => lv.wrapping_mul(rv),
                Op::Div => {
                    if rv == 0 {
                        return Err("division by zero".to_string());
                    }
                    lv / rv
                }
                Op::Mod => {
                    if rv == 0 {
                        return Err("modulo by zero".to_string());
                    }
                    lv % rv
                }
                Op::And => lv & rv,
                Op::Or => lv | rv,
                Op::Xor => lv ^ rv,
                Op::Shl => lv.wrapping_shl(rv as u32),
                Op::Shr => lv.wrapping_shr(rv as u32),
                _ => return Err(format!("unsupported binary operator: {:?}", op)),
            };
            Ok(res)
        }
        Expr::Member(base_expr, field) => {
            eval_member(base_expr, field, false, ctx)
        }
        Expr::PtrMember(base_expr, field) => {
            eval_member(base_expr, field, true, ctx)
        }
    }
}

/// `expr.field` または `expr->field` を評価します。
/// is_ptr=true のとき base_expr を先にデリファレンスします。
fn eval_member(
    base_expr: &Expr,
    field: &str,
    is_ptr: bool,
    ctx: &EvalContext,
) -> Result<u64, String> {
    let resolve_field = ctx.resolve_field.ok_or_else(|| {
        "struct field resolution not available".to_string()
    })?;

    // 変数名から型を取得してフィールドオフセットを解決する
    let base_var_name = match base_expr {
        Expr::Variable(n) => Some(n.as_str()),
        _ => None,
    };

    // base アドレスを取得
    let base_addr = if is_ptr {
        // -> : まず変数値 (ポインタ値) を読む
        eval(base_expr, ctx)?
    } else {
        // . : 変数のアドレスそのもの
        match base_var_name {
            Some(name) => {
                let addr_of = ctx.addr_of_var.ok_or_else(|| {
                    "address-of not available for '.'".to_string()
                })?;
                addr_of(name)?
            }
            None => {
                // 式の値をアドレスとして使う (例: (*p).field)
                eval(base_expr, ctx)?
            }
        }
    };

    // 型名を取得
    let type_name: String = if let Some(name) = base_var_name {
        let type_of = ctx.type_of_var.ok_or_else(|| {
            "type resolution not available".to_string()
        })?;
        let (tname, is_pointer, pointee) = type_of(name)?;
        if is_ptr {
            // -> : ポインタが指す型
            pointee
        } else {
            // . : 変数の型（ポインタなら除去）
            if is_pointer { pointee } else { tname }
        }
    } else {
        return Err(format!("cannot determine type for '{:?}'", base_expr));
    };

    let (offset, size) = resolve_field(&type_name, field)?;

    // base_addr + offset からメモリを読む
    let read = ctx.read_mem.ok_or_else(|| "memory read not available".to_string())?;
    let n = (size as usize).clamp(1, 8);
    let bytes = read((base_addr + offset) as usize, n)
        .map_err(|e| format!("failed to read {}.{}: {}", type_name, field, e))?;
    let size = n.min(bytes.len());
    let mut buf = [0u8; 8];
    if size > 0 {
        buf[..size].copy_from_slice(&bytes[..size]);
    }
    Ok(u64::from_le_bytes(buf))
}

struct Lexer<'a> {
    input: &'a str,
    pos: usize,
    peeked: Option<Token>,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            peeked: None,
        }
    }

    fn peek(&mut self) -> &Token {
        if self.peeked.is_none() {
            let tok = self.next_token();
            self.peeked = Some(tok);
        }
        self.peeked.as_ref().unwrap()
    }

    fn bump(&mut self) -> Token {
        if let Some(tok) = self.peeked.take() {
            tok
        } else {
            self.next_token()
        }
    }

    fn next_token(&mut self) -> Token {
        self.skip_whitespace();
        if self.pos >= self.input.len() {
            return Token::End;
        }
        let c = self.input[self.pos..].chars().next().unwrap();
        self.pos += c.len_utf8();
        match c {
            '+' => Token::Plus,
            '-' => {
                if self.pos < self.input.len() && self.input[self.pos..].starts_with('>') {
                    self.pos += '>'.len_utf8();
                    Token::Arrow
                } else {
                    Token::Minus
                }
            }
            '*' => Token::Mul,
            '/' => Token::Div,
            '%' => Token::Mod,
            '&' => Token::And,
            '|' => Token::Or,
            '^' => Token::Xor,
            '~' => Token::Not,
            '(' => Token::LParen,
            ')' => Token::RParen,
            '<' => {
                if self.pos < self.input.len() && self.input[self.pos..].starts_with('<') {
                    self.pos += '<'.len_utf8();
                    Token::Shl
                } else {
                    Token::End
                }
            }
            '>' => {
                if self.pos < self.input.len() && self.input[self.pos..].starts_with('>') {
                    self.pos += '>'.len_utf8();
                    Token::Shr
                } else {
                    Token::End
                }
            }
            '.' => Token::Dot,
            '$' => self.read_register(),
            '0'..='9' => self.read_number(),
            c if c.is_alphabetic() || c == '_' => self.read_ident(c),
            _ => Token::End,
        }
    }

    fn read_ident(&mut self, first: char) -> Token {
        let start = self.pos - first.len_utf8();
        while self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap();
            if c.is_alphanumeric() || c == '_' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        Token::Ident(self.input[start..self.pos].to_string())
    }

    fn read_register(&mut self) -> Token {
        let start = self.pos;
        while self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap();
            if c.is_alphanumeric() || c == '_' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        Token::Register(self.input[start..self.pos].to_string())
    }

    fn read_number(&mut self) -> Token {
        let start = self.pos - 1;
        let first = self.input[start..].chars().next().unwrap();
        if first == '0' && self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap();
            if c == 'x' || c == 'X' {
                self.pos += c.len_utf8();
                let val_start = self.pos;
                while self.pos < self.input.len() {
                    let c = self.input[self.pos..].chars().next().unwrap();
                    if c.is_ascii_hexdigit() {
                        self.pos += c.len_utf8();
                    } else {
                        break;
                    }
                }
                let s = &self.input[val_start..self.pos];
                if s.is_empty() {
                    return Token::Number(0);
                }
                return Token::Number(
                    u64::from_str_radix(s, 16).unwrap_or(0),
                );
            } else if c == 'b' || c == 'B' {
                self.pos += c.len_utf8();
                let val_start = self.pos;
                while self.pos < self.input.len() {
                    let c = self.input[self.pos..].chars().next().unwrap();
                    if c == '0' || c == '1' {
                        self.pos += c.len_utf8();
                    } else {
                        break;
                    }
                }
                let s = &self.input[val_start..self.pos];
                if s.is_empty() {
                    return Token::Number(0);
                }
                return Token::Number(u64::from_str_radix(s, 2).unwrap_or(0));
            } else if c == 'o' || c == 'O' {
                self.pos += c.len_utf8();
                let val_start = self.pos;
                while self.pos < self.input.len() {
                    let c = self.input[self.pos..].chars().next().unwrap();
                    if c.is_ascii_digit() && c != '8' && c != '9' {
                        self.pos += c.len_utf8();
                    } else {
                        break;
                    }
                }
                let s = &self.input[val_start..self.pos];
                if s.is_empty() {
                    return Token::Number(0);
                }
                return Token::Number(u64::from_str_radix(s, 8).unwrap_or(0));
            }
        }
        while self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap();
            if c.is_ascii_digit() {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        let s = &self.input[start..self.pos];
        Token::Number(s.parse().unwrap_or(0))
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            let c = self.input[self.pos..].chars().next().unwrap();
            if c.is_whitespace() {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
    }
}

struct Parser<'a> {
    lexer: Lexer<'a>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            lexer: Lexer::new(input),
        }
    }

    fn parse(&mut self) -> Result<Expr, String> {
        let expr = self.parse_or()?;
        if !matches!(self.lexer.peek(), Token::End) {
            return Err(format!("unexpected token: {:?}", self.lexer.peek()));
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_xor()?;
        while matches!(self.lexer.peek(), Token::Or) {
            self.lexer.bump();
            let right = self.parse_xor()?;
            left = Expr::Binary(Op::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_xor(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.lexer.peek(), Token::Xor) {
            self.lexer.bump();
            let right = self.parse_and()?;
            left = Expr::Binary(Op::Xor, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_shift()?;
        while matches!(self.lexer.peek(), Token::And) {
            self.lexer.bump();
            let right = self.parse_shift()?;
            left = Expr::Binary(Op::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_shift(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_add()?;
        loop {
            match self.lexer.peek() {
                Token::Shl => {
                    self.lexer.bump();
                    let right = self.parse_add()?;
                    left = Expr::Binary(Op::Shl, Box::new(left), Box::new(right));
                }
                Token::Shr => {
                    self.lexer.bump();
                    let right = self.parse_add()?;
                    left = Expr::Binary(Op::Shr, Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn parse_add(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_mul()?;
        loop {
            match self.lexer.peek() {
                Token::Plus => {
                    self.lexer.bump();
                    let right = self.parse_mul()?;
                    left = Expr::Binary(Op::Add, Box::new(left), Box::new(right));
                }
                Token::Minus => {
                    self.lexer.bump();
                    let right = self.parse_mul()?;
                    left = Expr::Binary(Op::Sub, Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_unary()?;
        loop {
            match self.lexer.peek() {
                Token::Mul => {
                    self.lexer.bump();
                    let right = self.parse_unary()?;
                    left = Expr::Binary(Op::Mul, Box::new(left), Box::new(right));
                }
                Token::Div => {
                    self.lexer.bump();
                    let right = self.parse_unary()?;
                    left = Expr::Binary(Op::Div, Box::new(left), Box::new(right));
                }
                Token::Mod => {
                    self.lexer.bump();
                    let right = self.parse_unary()?;
                    left = Expr::Binary(Op::Mod, Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        match self.lexer.peek() {
            Token::Plus => {
                self.lexer.bump();
                self.parse_unary()
            }
            Token::Minus => {
                self.lexer.bump();
                let inner = self.parse_unary()?;
                Ok(Expr::Unary(Op::Neg, Box::new(inner)))
            }
            Token::Not => {
                self.lexer.bump();
                let inner = self.parse_unary()?;
                Ok(Expr::Unary(Op::Not, Box::new(inner)))
            }
            Token::Mul => {
                self.lexer.bump();
                let inner = self.parse_unary()?;
                Ok(Expr::Unary(Op::Deref, Box::new(inner)))
            }
            Token::And => {
                // & 単項演算子: アドレス参照
                self.lexer.bump();
                let inner = self.parse_unary()?;
                Ok(Expr::Unary(Op::AddrOf, Box::new(inner)))
            }
            _ => self.parse_postfix(),
        }
    }

    /// プライマリ式の後に続く . / -> チェーンを処理します。
    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.parse_primary()?;
        loop {
            match self.lexer.peek() {
                Token::Dot => {
                    self.lexer.bump();
                    let field = match self.lexer.peek() {
                        Token::Ident(n) => { let n = n.clone(); self.lexer.bump(); n }
                        tok => return Err(format!("expected field name after '.', got {:?}", tok)),
                    };
                    expr = Expr::Member(Box::new(expr), field);
                }
                Token::Arrow => {
                    self.lexer.bump();
                    let field = match self.lexer.peek() {
                        Token::Ident(n) => { let n = n.clone(); self.lexer.bump(); n }
                        tok => return Err(format!("expected field name after '->', got {:?}", tok)),
                    };
                    expr = Expr::PtrMember(Box::new(expr), field);
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.lexer.peek() {
            Token::Number(n) => {
                let v = *n;
                self.lexer.bump();
                Ok(Expr::Number(v))
            }
            Token::Register(name) => {
                let name = name.clone();
                self.lexer.bump();
                Ok(Expr::Register(name))
            }
            Token::Ident(name) => {
                let name = name.clone();
                self.lexer.bump();
                Ok(Expr::Variable(name))
            }
            Token::LParen => {
                self.lexer.bump();
                let expr = self.parse_or()?;
                if !matches!(self.lexer.peek(), Token::RParen) {
                    return Err("expected ')'".to_string());
                }
                self.lexer.bump();
                Ok(expr)
            }
            tok => Err(format!("unexpected token: {:?}", tok)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_regs() -> ThreadState64 {
        #[cfg(target_arch = "x86_64")]
        {
            let mut r = ThreadState64::default();
            r.__rip = 0x1000;
            r.__rax = 0x10;
            r
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut r = ThreadState64::default();
            r.__pc = 0x1000;
            r.__x[0] = 0x10;
            r
        }
    }

    #[test]
    fn basic_arithmetic() {
        let expr = parse("1 + 2 * 3").unwrap();
        let regs = default_regs();
        let ctx = EvalContext::new(&regs, None, None);
        assert_eq!(eval(&expr, &ctx).unwrap(), 7);
    }

    #[test]
    fn register_and_hex() {
        let expr = parse("$pc + 0x10").unwrap();
        let regs = default_regs();
        let ctx = EvalContext::new(&regs, None, None);
        assert_eq!(eval(&expr, &ctx).unwrap(), 0x1010);
    }
}
