use std::{env, fs, io};

use anyhow::{Context, Result, bail};
use breez_sdk_spark::{
    BreezSdk, ChainApiType, EventListener, GetInfoRequest, Network, PaymentType,
    ReceivePaymentMethod, ReceivePaymentRequest, SdkBuilder, SdkEvent, Seed, SparkConfig,
    SparkSigningOperator, SparkSspConfig, default_config,
};
use tokio::{sync::mpsc, task};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const LOCAL_OPERATOR_PUBLIC_KEYS: [&str; 5] = [
    "0322ca18fc489ae25418a0e768273c2c61cabb823edfb14feb891e9bec62016510",
    "0341727a6c41b168f07eb50865ab8c397a53c7eef628ac1020956b705e43b6cb27",
    "0305ab8d485cc752394de4981f8a5ae004f2becfea6f432c9a59d5022d8764f0a6",
    "0352aef4d49439dedd798ac4aef1e7ebef95f569545b647a25338398c1247ffdea",
    "02c05c88cc8fc181b1ba30006df6a4b0597de6490e24514fbdd0266d2b9cd3d0ba",
];

struct ConsoleEventListener {
    event_sender: mpsc::UnboundedSender<SdkEvent>,
}

#[async_trait::async_trait]
impl EventListener for ConsoleEventListener {
    async fn on_event(&self, event: SdkEvent) {
        println!("sdk_event: {event}");
        let _ = self.event_sender.send(event);
    }
}

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
    let log_filter = env_or_default(
        "BREEZ_LOCAL_LOG_FILTER",
        "warn,spark_wallet=info,breez_sdk_spark=info",
    );

    init_console_logging(&log_filter)?;

    let operator_addresses =
        local_operator_addresses(operator_count, base_port, operator_domain.as_deref())?;
    fs::create_dir_all(&storage_dir)
        .with_context(|| format!("failed to create storage dir {storage_dir}"))?;

    let seed = Seed::Mnemonic {
        mnemonic,
        passphrase,
    };
    let mut config = default_config(Network::Local);
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

    let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
    let listener_id = sdk
        .add_event_listener(Box::new(ConsoleEventListener { event_sender }))
        .await;
    let info = sdk
        .get_info(GetInfoRequest {
            ensure_synced: Some(wait_for_sync),
        })
        .await?;
    let spark_address = sdk
        .receive_payment(ReceivePaymentRequest {
            payment_method: ReceivePaymentMethod::SparkAddress,
        })
        .await?
        .payment_request;

    println!("Spark wallet loaded.");
    println!("storage_dir: {storage_dir}");
    println!("electrs_url: {electrs_url}");
    println!("identity_pubkey: {}", info.identity_pubkey);
    println!("spark_address: {spark_address}");
    println!("balance_sats: {}", info.balance_sats);
    println!("token_balances: {:?}", info.token_balances);
    println!(
        "Watching server event stream. Heartbeat warnings will show as 'Received empty event, skipping'."
    );
    println!("Press Enter to disconnect and exit.");

    let enter_task = task::spawn_blocking(|| {
        let mut line = String::new();
        io::stdin().read_line(&mut line)
    });
    tokio::pin!(enter_task);

    loop {
        tokio::select! {
            read_result = &mut enter_task => {
                read_result
                    .context("failed waiting for Enter")?
                    .context("failed to read stdin")?;
                break;
            }
            Some(event) = event_receiver.recv() => {
                if let Some(context) = balance_log_context(&event) {
                    log_wallet_balance(&sdk, &context).await?;
                }
            }
        }
    }

    let _ = sdk.remove_event_listener(&listener_id).await;
    sdk.disconnect().await?;
    Ok(())
}

async fn log_wallet_balance(sdk: &BreezSdk, context: &str) -> Result<()> {
    let info = sdk
        .get_info(GetInfoRequest {
            ensure_synced: Some(false),
        })
        .await?;
    println!(
        "{context}: balance_sats={}, token_balances={:?}",
        info.balance_sats, info.token_balances
    );
    Ok(())
}

fn balance_log_context(event: &SdkEvent) -> Option<String> {
    match event {
        SdkEvent::PaymentSucceeded { payment } if payment.payment_type == PaymentType::Receive => {
            Some(format!(
                "received payment settled: id={}, method={}, amount={}",
                payment.id, payment.method, payment.amount
            ))
        }
        _ => None,
    }
}

fn init_console_logging(log_filter: &str) -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(log_filter))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(true)
                .with_line_number(true),
        )
        .try_init()?;
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
