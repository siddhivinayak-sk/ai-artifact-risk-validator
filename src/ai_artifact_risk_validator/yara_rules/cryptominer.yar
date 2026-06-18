/*
 * YARA rules for detecting crypto-mining indicators in AI artifact scripts.
 * Risk ID: Y-S3 (Cryptominer Match)
 */

rule CryptoMiner_StratumProtocol {
    meta:
        description = "Script containing Stratum mining protocol connection strings"
        severity = "HIGH"
        risk_id = "Y-S3"
    strings:
        $stratum1 = "stratum+tcp://" ascii nocase
        $stratum2 = "stratum+ssl://" ascii nocase
        $stratum3 = "stratum2+tcp://" ascii nocase
    condition:
        any of them
}

rule CryptoMiner_XMRWallet {
    meta:
        description = "Monero (XMR) wallet address detected"
        severity = "HIGH"
        risk_id = "Y-S3"
    strings:
        // Monero mainnet address: starts with 4, 43-95 chars Base58
        $xmr = /4[0-9A-Za-z]{93}/ ascii
    condition:
        $xmr
}

rule CryptoMiner_PoolDomains {
    meta:
        description = "Known crypto mining pool domain references"
        severity = "HIGH"
        risk_id = "Y-S3"
    strings:
        $pool1 = "xmrpool.eu" ascii nocase
        $pool2 = "moneroocean.stream" ascii nocase
        $pool3 = "nanopool.org" ascii nocase
        $pool4 = "supportxmr.com" ascii nocase
        $pool5 = "xmr.pool.minergate" ascii nocase
        $pool6 = "pool.minexmr.com" ascii nocase
    condition:
        any of them
}

rule CryptoMiner_XMRig {
    meta:
        description = "XMRig miner binary or configuration reference"
        severity = "HIGH"
        risk_id = "Y-S3"
    strings:
        $bin1 = "xmrig" ascii nocase
        $bin2 = "--donate-level" ascii
        $bin3 = "cpu-max-threads-hint" ascii
    condition:
        2 of them
}
