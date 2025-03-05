use anyhow::{Context, Result};
use log::{error, info};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;
use simplelog::*;
use std::error::Error;
use std::fs;
use time::macros::format_description;

use kybelith::QuantumBlockchainApp;

fn setup_logging() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let config = ConfigBuilder::new()
        .set_time_format_custom(format_description!("%Y-%m-%d %H:%M:%S"))
        .build();

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            config.clone(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Debug,
            config,
            fs::File::create("blockchain.log")?,
        ),
    ])?;

    Ok(())
}

fn main() -> Result<()> {
    if let Err(e) = setup_logging() {
        eprintln!("Erro ao configurar logging: {}", e);
    }

    info!("Iniciando aplicação blockchain quântica");

    // Gerar par de chaves para o nó
    let (public_key, secret_key) = dilithium5::keypair();

    // Inicializar a aplicação
    let mut app = QuantumBlockchainApp::new().context("Falha ao inicializar aplicação")?;

    // Registrar as chaves do administrador na blockchain
    let admin_address = "0x123...".to_string();

    // Usando o método as_bytes() através do trait
    app.blockchain
        .public_keys
        .insert(admin_address.clone(), public_key.as_bytes().to_vec());

    // Se necessário, também registrar a chave secreta
    app.blockchain
        .secret_keys
        .insert(admin_address.clone(), secret_key.clone());

    // ADICIONAR SALDO INICIAL DE KYBL PARA O ADMINISTRADOR
    // Este é o código que adicionamos para garantir que o administrador tenha KYBL suficiente
    if let Some(kybl_token) = app.blockchain.tokens.get_mut(&0.to_string()) {
        // Adicionar 1 milhão de KYBL para o administrador usar durante desenvolvimento
        *kybl_token
            .balances
            .entry(admin_address.clone())
            .or_insert(0) += 1_000_000;
        info!(
            "Adicionado saldo inicial de 1,000,000 KYBL ao administrador: {}",
            admin_address
        );
    } else {
        error!("Token KYBL (ID 0) não encontrado ao tentar adicionar saldo inicial");
    }

    info!(
        "Chaves do administrador registradas com sucesso: {}",
        admin_address
    );

    // Criar um token normal
    let token = app.create_token("MyToken".to_string(), "MTK".to_string(), 1_000_000)?;

    info!("Token criado: {} ({})", token.name, token.symbol);

    // Criar um token personalizado
    let custom_token_id = 1;
    let mut custom_token = app
        .create_custom_token(
            custom_token_id,
            "CustomToken".to_string(),
            "CTK".to_string(),
            500_000,
            admin_address.clone(),
        )
        .context("Falha ao criar token personalizado")?;

    info!(
        "Token personalizado criado: {} ({})",
        custom_token.name, custom_token.symbol
    );

    // Transferir tokens
    let transaction =
        app.transfer_token(&mut custom_token, "0x456...".to_string(), 1000, &secret_key)?;

    // Verificar a assinatura
    if !transaction.verify(&public_key, &transaction.signature)? {
        error!("Assinatura da transação inválida!");
        return Err(anyhow::anyhow!("Assinatura inválida"));
    }

    info!("Transferência realizada com sucesso e verificada");

    // Verificar a integridade da blockchain
    if !app.verify_chain_integrity()? {
        error!("Detectada violação de integridade na blockchain!");
        return Err(anyhow::anyhow!("Violação de integridade detectada"));
    }

    info!("Aplicação iniciada com sucesso");

    Ok(())
}
