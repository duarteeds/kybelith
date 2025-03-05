use super::Token;
use anyhow::Result;

pub struct TokenBuilder {
    name: Option<String>,
    symbol: Option<String>,
    total_supply: Option<u64>,
    creator: Option<String>,
}

impl TokenBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            symbol: None,
            total_supply: None,
            creator: None,
        }
    }

    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn symbol(mut self, symbol: String) -> Self {
        self.symbol = Some(symbol);
        self
    }

    pub fn total_supply(mut self, total_supply: u64) -> Self {
        self.total_supply = Some(total_supply);
        self
    }

    pub fn creator(mut self, creator: String) -> Self {
        self.creator = Some(creator);
        self
    }

    pub fn build(self) -> Result<Token> {
        let name = self
            .name
            .ok_or_else(|| anyhow::anyhow!("Nome não definido"))?;

        let symbol = self
            .symbol
            .ok_or_else(|| anyhow::anyhow!("Símbolo não definido"))?;

        let total_supply = self
            .total_supply
            .ok_or_else(|| anyhow::anyhow!("Fornecimento total não definido"))?;

        let creator = self
            .creator
            .ok_or_else(|| anyhow::anyhow!("Criador não definido"))?;

        Ok(Token::new(name, symbol, total_supply, creator)?)
    }
}
