use std::{env, fs};

use anyhow::{Context, Result, bail};
use breez_sdk_spark::{
    ChainApiType, GetInfoRequest, Network, SdkBuilder, Seed, SparkConfig, SparkSigningOperator,
    SparkSspConfig, default_config, init_logging,
};

const LOCAL_OPERATOR_PUBLIC_KEYS: [&str; 5] = [
    "0322ca18fc489ae25418a0e768273c2c61cabb823edfb14feb891e9bec62016510",
    "0341727a6c41b168f07eb50865ab8c397a53c7eef628ac1020956b705e43b6cb27",
    "0305ab8d485cc752394de4981f8a5ae004f2becfea6f432c9a59d5022d8764f0a6",
    "0352aef4d49439dedd798ac4aef1e7ebef95f569545b647a25338398c1247ffdea",
    "02c05c88cc8fc181b1ba30006df6a4b0597de6490e24514fbdd0266d2b9cd3d0ba",
];

#[tokio::main]
async fn main() -> Result<()> {
    let mnemonic = env::var("MNEMONIC")
        .or_else(|_| env::var("BREEZ_LOCAL_MNEMONIC"))
        .context("set MNEMONIC or BREEZ_LOCAL_MNEMONIC to a BIP-39 mnemonic")?;
    let passphrase = env::var("BREEZ_LOCAL_PASSPHRASE").ok();
    let storage_dir = env_or_default("BREEZ_LOCAL_DATA_DIR", "./.breez-local-wallet");
    let electrs_url = env_or_default("BREEZ_LOCAL_ELECTRS_URL", "http://127.0.0.1:30000");
    let ssp_url = env_or_default("BREEZ_LOCAL_SSP_URL", "http://127.0.0.1:5000");
    let operator_count = parse_env("BREEZ_LOCAL_OPERATOR_COUNT", 3_usize)?;
    let base_port = parse_env("BREEZ_LOCAL_OPERATOR_BASE_PORT", 8535_u16)?;
    let operator_domain = env::var("BREEZ_LOCAL_OPERATOR_DOMAIN")
        .ok()
        .filter(|value| !value.is_empty());
    let wait_for_sync = parse_bool_env("BREEZ_LOCAL_WAIT_FOR_SYNC", false)?;

    let operator_addresses =
        local_operator_addresses(operator_count, base_port, operator_domain.as_deref())?;
    fs::create_dir_all(&storage_dir)
        .with_context(|| format!("failed to create storage dir {storage_dir}"))?;
    init_logging(
        Some(storage_dir.clone()),
        None,
        Some("breez_sdk_spark=info,spark_wallet=info,spark=info".to_string()),
    )?;

    let seed = Seed::Mnemonic {
        mnemonic,
        passphrase,
    };
    let mut config = default_config(Network::Regtest);
    config.api_key = None;
    config.real_time_sync_server_url = None;
    config.lnurl_domain = None;
    config.private_enabled_default = false;
    config.spark_config = Some(local_spark_config(operator_addresses, ssp_url));

    let sdk = SdkBuilder::new(config, seed)
        .with_default_storage(storage_dir.clone())
        .with_rest_chain_service(electrs_url.clone(), ChainApiType::MempoolSpace, None)
        .build()
        .await?;

    let info = sdk
        .get_info(GetInfoRequest {
            ensure_synced: Some(wait_for_sync),
        })
        .await?;

    println!("Spark wallet loaded.");
    println!("storage_dir: {storage_dir}");
    println!("electrs_url: {electrs_url}");
    println!("identity_pubkey: {}", info.identity_pubkey);
    println!("balance_sats: {}", info.balance_sats);
    println!(
        "token_balances: {}",
        serde_json::to_string_pretty(&info.token_balances)?
    );

    sdk.disconnect().await?;
    Ok(())
}

fn local_spark_config(operator_addresses: Vec<String>, ssp_url: String) -> SparkConfig {
    let signing_operators = operator_addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| SparkSigningOperator {
            id: index as u32,
            identifier: operator_identifier(index),
            address,
            identity_public_key: LOCAL_OPERATOR_PUBLIC_KEYS[index].to_string(),
        })
        .collect::<Vec<_>>();

    let threshold = ((signing_operators.len() + 2) / 2) as u32;
    SparkConfig {
        coordinator_identifier: operator_identifier(0),
        threshold,
        signing_operators,
        ssp_config: SparkSspConfig {
            base_url: ssp_url,
            identity_public_key:
                "028c094a432d46a0ac95349d792c2e3730bd60c29188db716f56a99e39b95338b4"
                    .to_string(),
            schema_endpoint: Some("graphql/spark/rc".to_string()),
        },
        expected_withdraw_bond_sats: 10_000,
        expected_withdraw_relative_block_locktime: 1_000,
    }
}

fn operator_identifier(index: usize) -> String {
    format!("{:064x}", index + 1)
}

fn local_operator_addresses(
    operator_count: usize,
    base_port: u16,
    operator_domain: Option<&str>,
) -> Result<Vec<String>> {
    if operator_count == 0 {
        bail!("BREEZ_LOCAL_OPERATOR_COUNT must be at least 1");
    }
    if operator_count > LOCAL_OPERATOR_PUBLIC_KEYS.len() {
        bail!(
            "BREEZ_LOCAL_OPERATOR_COUNT={} is unsupported; max is {}",
            operator_count,
            LOCAL_OPERATOR_PUBLIC_KEYS.len()
        );
    }

    if let Some(domain) = operator_domain {
        return Ok((0..operator_count)
            .map(|index| format!("https://{index}.{domain}"))
            .collect());
    }

    Ok((0..operator_count)
        .map(|index| format!("https://localhost:{}", base_port + index as u16))
        .collect())
}

fn env_or_default(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn parse_env<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    match env::var(name) {
        Ok(value) => value
            .parse::<T>()
            .with_context(|| format!("failed to parse {name}={value}")),
        Err(_) => Ok(default),
    }
}

fn parse_bool_env(name: &str, default: bool) -> Result<bool> {
    match env::var(name) {
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "y" => Ok(true),
            "0" | "false" | "no" | "n" => Ok(false),
            _ => bail!("failed to parse {name}={value} as bool"),
        },
        Err(_) => Ok(default),
    }
}
