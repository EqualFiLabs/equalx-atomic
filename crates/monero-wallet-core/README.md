# Monero Wallet Core

## Example Usage

### Scanning for Owned Outputs

#### Stagenet/Regtest Setup

To run the example, you need to have a Monero node running on stagenet or regtest. Here’s how you can set up a node:

1. **Stagenet:**
   - Download and install Monero from [getmonero.org](https://www.getmonero.org/downloads/).
   - Start the Monero daemon with stagenet enabled:
     ```bash
     monerod --stagenet
     ```

2. **Regtest:**
   - Follow the same steps as above but start the Monero daemon with regtest enabled:
     ```bash
     monerod --regtest
     ```

#### Running the Example

After setting up your Monero node, you gican run the example using the following command:

```bash
cargo run -p monero-wallet-core --example scan_demo
```

This will scan a small range of blocks (from height 1,000,000 to 1,000,100) and print any owned outputs found.
