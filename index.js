/**
 * Firestore-safe Wallet Watcher Server (Price-Fallback Edition)
 * -------------------------------------------------------------
 * Features:
 * - Moralis primary data fetch (balances, NFTs, txs, net worth).
 * - Address-level token pricing (Moralis) + CoinGecko fallback (majors).
 * - Firestore-persisted last-known price fallback (prevents 0 USD floods).
 * - In-memory cache to reduce upstream calls.
 * - Native token pricing included in net worth.
 * - Analytics computed from priced tokens only (so you see real % values).
 * - Safe sanitization -> no "Nested arrays are not allowed" errors.
 * - Spam symbol & oversized metadata guards.
 */

require('dotenv').config();
const express = require('express');
const axios = require('axios');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

/* ------------------------------------------------------------------
 * Firebase Admin Init
 * ----------------------------------------------------------------*/
let serviceAccount;
try {
  if (process.env.SERVICE_ACCOUNT_BASE64) {
    serviceAccount = JSON.parse(
      Buffer.from(process.env.SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8')
    );
  }
} catch (err) {
  console.error('Failed to parse SERVICE_ACCOUNT_BASE64:', err);
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: serviceAccount
      ? admin.credential.cert(serviceAccount)
      : admin.credential.applicationDefault(),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
  });
}

const realtimeDB = admin.database();
const firestore = admin.firestore();

/* ------------------------------------------------------------------
 * Express App Setup
 * ----------------------------------------------------------------*/
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));

// Basic rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

/* ------------------------------------------------------------------
 * Env / Config
 * ----------------------------------------------------------------*/
const PORT = process.env.PORT || 3000;
const MORALIS_API_KEY = process.env.MORALIS_API_KEY;
if (!MORALIS_API_KEY) {
  console.warn('⚠️  MORALIS_API_KEY missing – server cannot fetch chain data.');
}

/** In-memory cache TTL (ms). Default 5m. Override w/ env PRICE_TTL_MS. */
const PRICE_TTL_MS = Number(process.env.PRICE_TTL_MS) || 5 * 60 * 1000;

/** How long a persisted Firestore price is considered usable (ms). Default 24h. */
const PRICE_PERSIST_MAX_AGE_MS =
  Number(process.env.PRICE_PERSIST_MAX_AGE_MS) || 24 * 60 * 60 * 1000;

/* ------------------------------------------------------------------
 * Chain Info
 * ----------------------------------------------------------------*/
const SUPPORTED_CHAINS = {
  eth: { name: 'Ethereum', nativeSymbol: 'ETH', decimals: 18 },
  polygon: { name: 'Polygon', nativeSymbol: 'MATIC', decimals: 18 },
  bsc: { name: 'BSC', nativeSymbol: 'BNB', decimals: 18 },
  avalanche: { name: 'Avalanche', nativeSymbol: 'AVAX', decimals: 18 },
};

/* ------------------------------------------------------------------
 * Spam / symbol guards
 * ----------------------------------------------------------------*/
const SPAM_PATTERN = /https?:\/\/|\s{2,}|\$|visit|claim|reward|bonus|airdrop/i;
const MAX_SYMBOL_LEN = 15; // skip extremely long junk symbols

/* ------------------------------------------------------------------
 * In-memory Price Cache
 *  key: tokenAddress(lower) OR symbol(UPPER) fallback OR "native-<chain>"
 *  value: { priceUsd, changePercent24h, logo, decimals?, ts }
 * ----------------------------------------------------------------*/
const PRICE_CACHE = new Map();

function getCachedPrice(key) {
  const entry = PRICE_CACHE.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > PRICE_TTL_MS) {
    PRICE_CACHE.delete(key);
    return null;
  }
  return entry.value;
}
function setCachedPrice(key, value) {
  PRICE_CACHE.set(key, { value, ts: Date.now() });
}

/* ------------------------------------------------------------------
 * Firestore Price Persistence
 *  Collection: TOKEN_PRICES
 *  DocID: <chain>_<tokenAddressLower>  (native assets use <chain>_native)
 *  Fields: { lastUsd, lastChange24h, logo, decimals, updatedAt (Timestamp) }
 * ----------------------------------------------------------------*/
function tokenPriceDocId(chain, tokenAddressOrNativeKey) {
  return `${chain}_${tokenAddressOrNativeKey.toLowerCase()}`;
}
function tokenPriceDocRef(chain, tokenAddressOrNativeKey) {
  return firestore.collection('TOKEN_PRICES').doc(tokenPriceDocId(chain, tokenAddressOrNativeKey));
}

/** Load last-known price from Firestore (if fresh enough). */
async function loadPersistedTokenPrice(chain, tokenAddressOrNativeKey) {
  try {
    const doc = await tokenPriceDocRef(chain, tokenAddressOrNativeKey).get();
    if (!doc.exists) return null;
    const data = doc.data();
    if (!data?.updatedAt) return null;
    const updatedAt = data.updatedAt.toMillis ? data.updatedAt.toMillis() : Date.parse(data.updatedAt);
    if (!updatedAt) return null;
    if (Date.now() - updatedAt > PRICE_PERSIST_MAX_AGE_MS) return null;
    return {
      priceUsd: Number(data.lastUsd || 0),
      changePercent24h: Number(data.lastChange24h || 0),
      logo: data.logo ?? null,
      decimals: data.decimals,
    };
  } catch (err) {
    console.error('loadPersistedTokenPrice error:', err.message);
    return null;
  }
}

/** Persist a token price to Firestore (async best-effort; not fatal). */
async function persistTokenPrice(chain, tokenAddressOrNativeKey, priceData) {
  try {
    await tokenPriceDocRef(chain, tokenAddressOrNativeKey).set(
      {
        chain,
        tokenAddress: tokenAddressOrNativeKey,
        lastUsd: priceData.priceUsd ?? 0,
        lastChange24h: priceData.changePercent24h ?? 0,
        logo: priceData.logo ?? null,
        decimals: priceData.decimals ?? null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  } catch (err) {
    console.error('persistTokenPrice error:', err.message);
  }
}

/* ------------------------------------------------------------------
 * Minimal CoinGecko ID map (majors only – reduces 429s)
 * Extend this as you need more assets.
 * ----------------------------------------------------------------*/
const COINGECKO_ID_MAP = {
  ETH: 'ethereum',
  WETH: 'weth',
  USDT: 'tether',
  USDC: 'usd-coin',
  DAI: 'dai',
  WBTC: 'wrapped-bitcoin',
  BNB: 'binancecoin',
  MATIC: 'matic-network',
  AVAX: 'avalanche-2',
  UNI: 'uniswap',
  LINK: 'chainlink',
  APE: 'apecoin',
};

/* ------------------------------------------------------------------
 * Moralis API Helpers
 * ----------------------------------------------------------------*/
const MORALIS_BASE = 'https://deep-index.moralis.io/api/v2.2';
function moralisHeaders() {
  return {
    'X-API-Key': MORALIS_API_KEY,
    accept: 'application/json',
  };
}
async function moralisGet(path, params = {}, timeout = 20_000) {
  const url = `${MORALIS_BASE}${path}`;
  const { data } = await axios.get(url, { headers: moralisHeaders(), params, timeout });
  return data;
}

/* ------------------------------------------------------------------
 * CoinGecko Price (symbol‑based fallback)
 * ----------------------------------------------------------------*/
async function fetchCoinGeckoPrice(symbol) {
  if (!symbol) return { priceUsd: 0, changePercent24h: 0, logo: null };
  const upper = symbol.toUpperCase();
  if (SPAM_PATTERN.test(symbol) || symbol.length > MAX_SYMBOL_LEN) {
    return { priceUsd: 0, changePercent24h: 0, logo: null };
  }
  const cached = getCachedPrice(upper);
  if (cached) return cached;

  const id = COINGECKO_ID_MAP[upper];
  if (!id) {
    const v = { priceUsd: 0, changePercent24h: 0, logo: null };
    setCachedPrice(upper, v);
    return v;
  }

  try {
    const url = 'https://api.coingecko.com/api/v3/simple/price';
    const { data } = await axios.get(url, {
      params: { ids: id, vs_currencies: 'usd', include_24hr_change: 'true' },
      timeout: 10_000,
    });
    const d = data[id] || {};
    const v = {
      priceUsd: d.usd || 0,
      changePercent24h: d.usd_24h_change || 0,
      logo: null, // skipping logo to reduce traffic
    };
    setCachedPrice(upper, v);
    return v;
  } catch (err) {
    console.error(`CoinGecko price error for ${symbol}:`, err.message);
    const v = { priceUsd: 0, changePercent24h: 0, logo: null };
    setCachedPrice(upper, v);
    return v;
  }
}

/* ------------------------------------------------------------------
 * Moralis Token Price (address‑based primary source)
 * ----------------------------------------------------------------*/
async function fetchMoralisTokenPrice(tokenAddress, chain) {
  if (!tokenAddress) return null;
  const key = tokenAddress.toLowerCase();
  const cached = getCachedPrice(key);
  if (cached) return cached;

  try {
    const url = `${MORALIS_BASE}/erc20/${tokenAddress}/price`;
    const { data } = await axios.get(url, {
      headers: moralisHeaders(),
      params: { chain },
      timeout: 10_000,
    });
    const v = {
      priceUsd: Number(data.usdPrice ?? 0),
      changePercent24h: 0, // Moralis price endpoint doesn't include percent change
      logo: data.tokenLogo ?? null,
      decimals: data.decimals ?? undefined,
    };
    setCachedPrice(key, v);
    // Persist
    persistTokenPrice(chain, key, v);
    return v;
  } catch (err) {
    console.error(`Moralis token price error ${tokenAddress} (${chain}):`, err.message);
    return null; // don't cache failure so we can try fallback
  }
}

/* ------------------------------------------------------------------
 * Helper: safeSymbol
 * ----------------------------------------------------------------*/
function safeSymbol(sym) {
  if (!sym) return '';
  const cleaned = String(sym).trim();
  if (SPAM_PATTERN.test(cleaned)) return '';
  if (cleaned.length > MAX_SYMBOL_LEN) return cleaned.slice(0, MAX_SYMBOL_LEN);
  return cleaned;
}

/* ------------------------------------------------------------------
 * NFT image resolution
 * ----------------------------------------------------------------*/
function ipfsToHttp(uri) {
  if (!uri) return null;
  if (uri.startsWith('ipfs://')) {
    return `https://ipfs.io/ipfs/${uri.slice('ipfs://'.length)}`;
  }
  return uri;
}

function extractImageFromMetadataObj(meta) {
  if (!meta || typeof meta !== 'object') return null;
  return (
    ipfsToHttp(meta.image) ||
    ipfsToHttp(meta.image_url) ||
    ipfsToHttp(meta.imageUrl) ||
    null
  );
}

function parseMetadataMaybe(strOrObj) {
  if (!strOrObj) return null;
  if (typeof strOrObj === 'object') return strOrObj;
  if (typeof strOrObj === 'string') {
    try {
      return JSON.parse(strOrObj);
    } catch (_) {
      return null;
    }
  }
  return null;
}

function resolveNftImage(nft) {
  // 1. direct known fields
  const direct =
    nft.image ||
    nft.image_url ||
    nft.normalized_metadata?.image ||
    nft.metadata?.image ||
    null;

  if (direct) return ipfsToHttp(direct);

  // 2. metadata string/object
  const meta = parseMetadataMaybe(nft.metadata);
  const fromMeta = extractImageFromMetadataObj(meta);
  if (fromMeta) return fromMeta;

  // 3. token_uri (could be ipfs or direct image)
  if (nft.token_uri) {
    if (/\.(png|jpe?g|gif|webp|svg)$/i.test(nft.token_uri)) {
      return ipfsToHttp(nft.token_uri);
    }
    if (nft.token_uri.startsWith('ipfs://')) {
      return ipfsToHttp(nft.token_uri);
    }
  }

  return null;
}

/* ------------------------------------------------------------------
 * Map Moralis Native Balance -> App
 * ----------------------------------------------------------------*/
function mapNativeBalance(data, chain) {
  const chainInfo = SUPPORTED_CHAINS[chain] || SUPPORTED_CHAINS.eth;
  const bal = data?.balance ?? '0';
  return {
    balance: String(bal),
    symbol: chainInfo.nativeSymbol,
    decimals: chainInfo.decimals,
  };
}

/* ------------------------------------------------------------------
 * Map Moralis Token -> App (no pricing yet)
 * ----------------------------------------------------------------*/
function mapToken(token) {
  const symbol = safeSymbol(token.symbol);
  const balanceRaw = token.balance ?? '0';
  const decimals = Number.isFinite(Number(token.decimals)) ? Number(token.decimals) : 0;
  const readableBalance =
    decimals > 0 ? Number(balanceRaw) / Math.pow(10, decimals) : Number(balanceRaw);

  return {
    tokenAddress: (token.token_address || token.address || '').toLowerCase(),
    name: token.name || symbol,
    symbol,
    balance: String(balanceRaw),
    decimals,
    readableBalance: isFinite(readableBalance) ? readableBalance : 0,
    valueUsd: 0,
    priceUsd: 0,
    changePercent24h: 0,
    logo: token.logo || null,
  };
}

/* ------------------------------------------------------------------
 * Map Moralis NFT -> App
 * ----------------------------------------------------------------*/
function mapNft(nft) {
  return {
    tokenAddress: (nft.token_address || nft.tokenAddress || '').toLowerCase(),
    tokenId: String(nft.token_id ?? nft.tokenId ?? ''),
    name: nft.name ?? null,
    symbol: nft.symbol ?? null,
    image: resolveNftImage(nft),
    metadata: null, // drop heavy metadata (optional: keep truncated)
  };
}

/* ------------------------------------------------------------------
 * Map Moralis Tx -> App (pricing filled later if needed)
 * ----------------------------------------------------------------*/
function mapTx(tx, address, chain) {
  const lowerUser = address.toLowerCase();
  const from = (tx.from_address || '').toLowerCase();
  const isSend = from === lowerUser;
  const type = isSend ? 'send' : 'receive';

  const chainInfo = SUPPORTED_CHAINS[chain] || SUPPORTED_CHAINS.eth;

  // If value>0 treat as native; else attempt ERC20
  let assetType = tx.value && tx.value !== '0' ? 'native' : 'ERC20';
  let symbol = chainInfo.nativeSymbol;
  let name = chainInfo.name;
  let amount = 0;

  if (assetType === 'native') {
    amount = Number(tx.value || 0) / Math.pow(10, chainInfo.decimals);
  } else {
    // try logs
    if (Array.isArray(tx.logs)) {
      for (const l of tx.logs) {
        const dec = l?.decoded_event;
        if (dec?.name === 'Transfer') {
          const params = dec.params || [];
          const val = params.find((p) => p.name === 'value');
          const sym = params.find((p) => p.name === 'symbol');
          const decs = params.find((p) => p.name === 'decimals');
          if (sym?.value) symbol = safeSymbol(sym.value);
          const d = Number(decs?.value) || 18;
          amount = val?.value ? Number(val.value) / Math.pow(10, d) : 0;
          break;
        }
      }
    }
  }

  return {
    hash: tx.hash || '',
    type,
    assetType,
    symbol,
    name,
    logo: null,
    amount,
    amountUsd: 0, // fill later if you want tx USD
    fromAddress: tx.from_address || '',
    toAddress: tx.to_address || '',
    timestamp: tx.block_timestamp || '',
  };
}

/* ------------------------------------------------------------------
 * Analytics builder (ignores tokens w/ no price)
 * ----------------------------------------------------------------*/
function computeAnalytics(tokenList) {
  const priced = tokenList.filter((t) => t.priceUsd && t.priceUsd > 0 && t.valueUsd > 0);
  const total = priced.reduce((s, t) => s + Number(t.valueUsd || 0), 0);

  const sorted = [...priced].sort(
    (a, b) => (b.valueUsd || 0) - (a.valueUsd || 0)
  );
  const top = sorted[0] || null;

  const pie = priced.map((t) => ({
    name: t.symbol || t.name || '',
    valueUsd: t.valueUsd || 0,
    sharePercent: total > 0 ? ((t.valueUsd || 0) / total * 100).toFixed(2) : '0.00',
  }));

  return {
    totalTokenValueUsd: total,
    topToken: top
      ? {
          name: top.symbol || top.name || '',
          valueUsd: top.valueUsd || 0,
          sharePercent: total > 0 ? ((top.valueUsd || 0) / total * 100).toFixed(2) : '0.00',
        }
      : { name: '', valueUsd: 0, sharePercent: '0.00' },
    tokenDistribution: pie,
  };
}

/* ------------------------------------------------------------------
 * Extract token price map from Moralis Net Worth payload
 *   Handles several possible shapes.
 * ----------------------------------------------------------------*/
function buildPriceMapFromNetWorth(netWorthRes) {
  const map = {};
  if (!netWorthRes) return map;

  // Helper to record into map
  function record(addr, priceUsd, logo, changePercent24h, decimals) {
    if (!addr) return;
    const key = addr.toLowerCase();
    if (!map[key]) {
      map[key] = {
        priceUsd: Number(priceUsd ?? 0),
        changePercent24h: Number(changePercent24h ?? 0),
        logo: logo ?? null,
        decimals,
      };
    }
  }

  // If top-level has token info
  if (Array.isArray(netWorthRes.tokens)) {
    for (const t of netWorthRes.tokens) {
      record(
        t.token_address || t.address,
        t.usd_price ?? t.price_usd ?? t.usdPrice,
        t.logo,
        t.usd_24h_change_pct ?? t.changePercent24h,
        t.decimals
      );
    }
  }

  // If top-level has chains
  if (netWorthRes.chains && typeof netWorthRes.chains === 'object') {
    Object.values(netWorthRes.chains).forEach((c) => {
      if (Array.isArray(c.tokens)) {
        c.tokens.forEach((t) =>
          record(
            t.token_address || t.address,
            t.usd_price ?? t.price_usd ?? t.usdPrice,
            t.logo,
            t.usd_24h_change_pct ?? t.changePercent24h,
            t.decimals
          )
        );
      }
      if (Array.isArray(c.portfolio_items)) {
        c.portfolio_items.forEach((t) =>
          record(
            t.token_address || t.address,
            t.usd_price ?? t.price_usd ?? t.usdPrice,
            t.logo,
            t.usd_24h_change_pct ?? t.changePercent24h,
            t.decimals
          )
        );
      }
    });
  }

  if (Array.isArray(netWorthRes.portfolio_items)) {
    netWorthRes.portfolio_items.forEach((t) =>
      record(
        t.token_address || t.address,
        t.usd_price ?? t.price_usd ?? t.usdPrice,
        t.logo,
        t.usd_24h_change_pct ?? t.changePercent24h,
        t.decimals
      )
    );
  }

  return map;
}

/* ------------------------------------------------------------------
 * Enrich token list with prices
 *   Order:
 *    1. priceMap from Moralis net worth payload (if any)
 *    2. Persisted Firestore last-known price
 *    3. Moralis live per-token price
 *    4. CoinGecko (majors by symbol)
 * ----------------------------------------------------------------*/
async function enrichTokensWithPrices(tokens, chain, priceMap) {
  const missing = [];

  // 1. Apply Moralis Net Worth price map
  for (const t of tokens) {
    const key = t.tokenAddress?.toLowerCase();
    const pm = key ? priceMap[key] : null;
    if (pm && pm.priceUsd > 0) {
      t.priceUsd = pm.priceUsd;
      t.changePercent24h = pm.changePercent24h ?? 0;
      t.logo = pm.logo ?? t.logo ?? null;
      if (pm.decimals != null && !isNaN(pm.decimals) && t.decimals === 0) {
        t.decimals = Number(pm.decimals);
      }
    } else {
      missing.push(t);
    }
  }

  // 2. Load persisted last-known price from Firestore
  const stillMissing = [];
  await Promise.all(
    missing.map(async (tok) => {
      const key = tok.tokenAddress;
      const persisted = await loadPersistedTokenPrice(chain, key);
      if (persisted && persisted.priceUsd > 0) {
        tok.priceUsd = persisted.priceUsd;
        tok.changePercent24h = persisted.changePercent24h ?? 0;
        tok.logo = persisted.logo ?? tok.logo ?? null;
        if (persisted.decimals != null && !isNaN(persisted.decimals) && tok.decimals === 0) {
          tok.decimals = Number(persisted.decimals);
        }
      } else {
        stillMissing.push(tok);
      }
    })
  );

  // 3. Moralis live per-token price for those still missing
  const batchSize = 5;
  for (let i = 0; i < stillMissing.length; i += batchSize) {
    const batch = stillMissing.slice(i, i + batchSize);
    await Promise.all(
      batch.map(async (tok) => {
        const p = await fetchMoralisTokenPrice(tok.tokenAddress, chain);
        if (p && p.priceUsd > 0) {
          tok.priceUsd = p.priceUsd;
          tok.changePercent24h = p.changePercent24h ?? 0;
          tok.logo = p.logo ?? tok.logo ?? null;
          if (p.decimals != null && !isNaN(p.decimals) && tok.decimals === 0) {
            tok.decimals = Number(p.decimals);
          }
        }
      })
    );
    await new Promise((r) => setTimeout(r, 200));
  }

  // 4. CoinGecko fallback for majors (symbol only)
  for (const t of tokens) {
    if (t.priceUsd && t.priceUsd > 0) continue;
    const priceData = await fetchCoinGeckoPrice(t.symbol);
    if (priceData.priceUsd > 0) {
      t.priceUsd = priceData.priceUsd;
      t.changePercent24h = priceData.changePercent24h;
      t.logo = priceData.logo ?? t.logo;
      // persist keyed by symbol? We persist by address only when known; skip here.
    }
  }

  // Recompute valueUsd after final pricing
  for (const t of tokens) {
    t.valueUsd = (t.readableBalance || 0) * (t.priceUsd || 0);
  }

  return tokens;
}

/* ------------------------------------------------------------------
 * Compute Net Worth total
 * ----------------------------------------------------------------*/
async function computeNetWorthUsd(netRes, tokens, nativeBalance, chain) {
  // 1. Try Moralis net worth payload
  if (netRes) {
    const total =
      netRes.total_networth_usd ??
      netRes.total_net_worth_usd ??
      netRes.net_worth_usd ??
      netRes.usd_total ??
      null;
    if (total != null) return Number(total);
  }

  // 2. Local compute: token USD + native USD
  let totalToken = 0;
  for (const t of tokens) {
    if (t.priceUsd > 0) totalToken += Number(t.valueUsd || 0);
  }

  let nativeUsd = 0;
  if (nativeBalance) {
    const chainInfo = SUPPORTED_CHAINS[chain] || SUPPORTED_CHAINS.eth;
    const nativeBal =
      Number(nativeBalance.balance || 0) / Math.pow(10, nativeBalance.decimals || chainInfo.decimals);

    // Try cache -> persisted -> CG
    const nativeCacheKey = `native-${chain}`;
    let nativePrice = getCachedPrice(nativeCacheKey);
    if (!nativePrice) {
      const persisted = await loadPersistedTokenPrice(chain, 'native');
      if (persisted && persisted.priceUsd > 0) {
        nativePrice = persisted;
        setCachedPrice(nativeCacheKey, nativePrice);
      } else {
        const cg = await fetchCoinGeckoPrice(chainInfo.nativeSymbol);
        nativePrice = cg;
        setCachedPrice(nativeCacheKey, nativePrice);
        persistTokenPrice(chain, 'native', nativePrice);
      }
    }
    nativeUsd = nativeBal * (nativePrice.priceUsd || 0);
  }

  return totalToken + nativeUsd;
}

/* ------------------------------------------------------------------
 * SANITIZER – Firestore-safe deep clone (no nested arrays; clean NaN)
 * ----------------------------------------------------------------*/
function sanitizeForFirestore(value) {
  if (Array.isArray(value)) {
    const out = [];
    for (const item of value) {
      if (Array.isArray(item)) continue; // drop nested arrays
      out.push(sanitizeForFirestore(item));
    }
    return out;
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined) continue;
      out[k] = sanitizeForFirestore(v);
    }
    return out;
  }
  if (typeof value === 'number') {
    if (!isFinite(value) || isNaN(value)) return 0;
    return value;
  }
  if (value === undefined) return null;
  return value;
}

/* ------------------------------------------------------------------
 * fetchComprehensiveWalletData()
 * ----------------------------------------------------------------*/
async function fetchComprehensiveWalletData(address, chain = 'eth') {
  try {
    const params = { chain };

    const [nativeRes, tokenRes, nftRes, txRes, netRes] = await Promise.allSettled([
      moralisGet(`/${address}/balance`, params),
      moralisGet(`/${address}/erc20`, params),
      moralisGet(`/${address}/nft`, { ...params, format: 'decimal', limit: 100 }),
      moralisGet(`/${address}`, { ...params, limit: 10 }),
      moralisGet(`/wallets/${address}/net-worth`, { chains: chain }),
    ]);

    /* ----- Native Balance ----- */
    const nativeBalance =
      nativeRes.status === 'fulfilled' ? mapNativeBalance(nativeRes.value, chain) : null;

    /* ----- Tokens ----- */
    const rawTokens = tokenRes.status === 'fulfilled' ? tokenRes.value : [];
    const tokenList = Array.isArray(rawTokens)
      ? rawTokens
      : Array.isArray(rawTokens?.result)
      ? rawTokens.result
      : [];
    const mappedTokens = tokenList.map(mapToken);

    /* ----- NFTs ----- */
    const rawNfts = nftRes.status === 'fulfilled' ? nftRes.value : [];
    const nftArr = Array.isArray(rawNfts)
      ? rawNfts
      : Array.isArray(rawNfts?.result)
      ? rawNfts.result
      : [];
    const nftBalances = nftArr.map(mapNft);

    /* ----- Transactions ----- */
    const txPayload = txRes.status === 'fulfilled' ? txRes.value : null;
    const rawTxs = Array.isArray(txPayload?.result) ? txPayload.result : [];
    const recentTransactions = rawTxs.map((tx) => mapTx(tx, address, chain));

    /* ----- Price Map from Net Worth ----- */
    const netWorthPayload = netRes.status === 'fulfilled' ? netRes.value : null;
    const priceMap = buildPriceMapFromNetWorth(netWorthPayload);

    // also store native under synthetic key (populate if available)
    const chainInfo = SUPPORTED_CHAINS[chain] || SUPPORTED_CHAINS.eth;
    const nativeKey = `native-${chain}`;
    if (netWorthPayload?.chains?.[chain]?.native_token) {
      const nat = netWorthPayload.chains[chain].native_token;
      priceMap[nativeKey] = {
        priceUsd: Number(nat.usd_price ?? 0),
        changePercent24h: Number(nat.usd_24h_change_pct ?? 0),
        logo: nat.logo ?? null,
      };
      // persist
      persistTokenPrice(chain, 'native', priceMap[nativeKey]);
      setCachedPrice(nativeKey, priceMap[nativeKey]);
    }

    /* ----- Enrich tokens with prices ----- */
    await enrichTokensWithPrices(mappedTokens, chain, priceMap);

    /* ----- Recompute Net Worth ----- */
    const totalNetworthUsd = await computeNetWorthUsd(
      netWorthPayload,
      mappedTokens,
      nativeBalance,
      chain
    );
    const netWorth = { totalNetworthUsd };

    /* ----- Analytics ----- */
    const analytics = computeAnalytics(mappedTokens);

    /* ----- Build walletData ----- */
    const walletData = {
      address,
      chain,
      fetchedAt: new Date().toISOString(),
      nativeBalance,
      tokenBalances: mappedTokens,
      nftBalances,
      recentTransactions,
      netWorth,
      analytics,
      errors: [],
    };

    /* ----- Record errors for each fetch ----- */
    const errorTypes = ['nativeBalance', 'tokenBalances', 'nftBalances', 'transactions', 'netWorth'];
    [nativeRes, tokenRes, nftRes, txRes, netRes].forEach((r, i) => {
      if (r.status === 'rejected') {
        walletData.errors.push({
          type: errorTypes[i],
          error: r.reason?.message || String(r.reason),
        });
      }
    });

    return walletData;
  } catch (error) {
    console.error(`❌ Error fetching wallet data for ${address}:`, error);
    return {
      address,
      chain,
      fetchedAt: new Date().toISOString(),
      nativeBalance: null,
      tokenBalances: [],
      nftBalances: [],
      recentTransactions: [],
      netWorth: { totalNetworthUsd: 0 },
      analytics: {
        totalTokenValueUsd: 0,
        topToken: { name: '', valueUsd: 0, sharePercent: '0.00' },
        tokenDistribution: [],
      },
      errors: [{ type: 'general', error: error.message }],
      error: error.message,
      success: false,
    };
  }
}

/* ------------------------------------------------------------------
 * Active Wallets – from Realtime DB
 * ----------------------------------------------------------------*/
async function getActiveWallets() {
  try {
    const usersRef = realtimeDB.ref('USERS');
    const snapshot = await usersRef.once('value');
    const users = snapshot.val();
    const activeWallets = [];

    if (!users) {
      console.log('No users found in database');
      return [];
    }

    for (const userKey in users) {
      const user = users[userKey];
      if (user.wallets) {
        for (const walletAddr in user.wallets) {
          const wallet = user.wallets[walletAddr];
          if (wallet.choosen === true || wallet.choosen === 'true') {
            activeWallets.push({
              userId: userKey,
              address: walletAddr,
              walletData: wallet,
            });
          }
        }
      }
    }
    return activeWallets;
  } catch (error) {
    console.error('❌ Error getting active wallets:', error);
    return [];
  }
}

/* ------------------------------------------------------------------
 * Store Wallet Data – Firestore-safe
 * ----------------------------------------------------------------*/
async function storeWalletData(userId, address, walletData) {
  try {
    const walletDocRef = firestore
      .collection('USERS')
      .doc(userId)
      .collection('wallets')
      .doc(address);

    // Firestore-safe clone
    const clean = sanitizeForFirestore(walletData);

    const firestoreData = {
      userId,
      address,
      ...clean,
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(), // merge-safe; won't overwrite existing non-null
    };

    await walletDocRef.set(firestoreData, { merge: true });

    // update lastSync in Realtime DB
    await realtimeDB
      .ref(`USERS/${userId}/wallets/${address}/lastSync`)
      .set(new Date().toISOString());

    console.log(`✅ Stored data for wallet: ${address} (User: ${userId})`);
    return true;
  } catch (error) {
    console.error(`❌ Error storing wallet data for ${address}:`, error);
    return false;
  }
}

/* ------------------------------------------------------------------
 * Routes
 * ----------------------------------------------------------------*/

// Sync ALL active wallets
app.get('/api/sync-wallets', async (req, res) => {
  try {
    const activeWallets = await getActiveWallets();
    const results = [];

    if (activeWallets.length === 0) {
      return res
        .status(200)
        .json({ message: 'No active wallets found', synced: 0, results: [] });
    }

    console.log(`🔄 Syncing ${activeWallets.length} active wallets...`);

    // smaller batch reduces upstream API failures
    const batchSize = 2;
    for (let i = 0; i < activeWallets.length; i += batchSize) {
      const batch = activeWallets.slice(i, i + batchSize);
      for (const wallet of batch) {
        const walletData = await fetchComprehensiveWalletData(wallet.address);
        const stored = await storeWalletData(
          wallet.userId,
          wallet.address,
          walletData
        );
        results.push({
          address: wallet.address,
          userId: wallet.userId,
          success: stored && !walletData.error,
          data: walletData,
        });
      }
      if (i + batchSize < activeWallets.length) {
        await new Promise((r) => setTimeout(r, 750));
      }
    }

    const successful = results.filter((r) => r.success).length;
    const failed = results.filter((r) => !r.success).length;

    res.status(200).json({
      message: 'Wallet sync completed',
      synced: successful,
      failed,
      total: activeWallets.length,
      results,
    });
  } catch (error) {
    console.error('❌ Server Error in sync-wallets:', error);
    res
      .status(500)
      .json({ error: 'Internal server error', message: error.message });
  }
});

// Sync ONE wallet
app.post('/api/sync-wallet', async (req, res) => {
  try {
    const { address, userId, chain = 'eth' } = req.body || {};

    if (!address || !userId) {
      return res.status(400).json({ error: 'Address and userId are required' });
    }
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return res.status(400).json({ error: 'Invalid Ethereum address format' });
    }

    const walletData = await fetchComprehensiveWalletData(address, chain);
    const stored = await storeWalletData(userId, address, walletData);

    if (stored && !walletData.error) {
      res
        .status(200)
        .json({ message: 'Wallet synced successfully', address, data: walletData });
    } else {
      res
        .status(500)
        .json({
          error: 'Failed to sync wallet',
          address,
          details: walletData.error || 'Storage failed',
        });
    }
  } catch (error) {
    console.error('❌ Error in sync-wallet:', error);
    res
      .status(500)
      .json({ error: 'Internal server error', message: error.message });
  }
});

// Webhook from Moralis
app.post('/api/webhook/moralis', async (req, res) => {
  try {
    const webhookData = req.body;
    console.log('📥 Received webhook:', JSON.stringify(webhookData, null, 2));

    const address = webhookData.address || webhookData.from || webhookData.to;
    if (!address) {
      return res.status(400).json({ error: 'No address found in webhook data' });
    }

    const activeWallets = await getActiveWallets();
    const matchingWallet = activeWallets.find(
      (w) => w.address.toLowerCase() === address.toLowerCase()
    );

    if (matchingWallet) {
      console.log(`🔄 Webhook triggered sync for ${address}`);
      const walletData = await fetchComprehensiveWalletData(address);
      await storeWalletData(matchingWallet.userId, address, walletData);
      res
        .status(200)
        .json({ message: 'Webhook processed successfully', address, updated: true });
    } else {
      console.log(`ℹ️ Webhook received for non-active wallet: ${address}`);
      res
        .status(200)
        .json({
          message: 'Webhook received but address not in active wallets',
          address,
          updated: false,
        });
    }
  } catch (error) {
    console.error('❌ Error processing webhook:', error);
    res
      .status(500)
      .json({ error: 'Error processing webhook', message: error.message });
  }
});

// Get wallet doc
app.get('/api/wallet/:userId/:address', async (req, res) => {
  try {
    const { userId, address } = req.params;
    const walletDocRef = firestore
      .collection('USERS')
      .doc(userId)
      .collection('wallets')
      .doc(address);
    const doc = await walletDocRef.get();
    if (!doc.exists) {
      return res.status(404).json({
        error: 'Wallet data not found',
        message: 'No wallet data found in Firestore for this user and address',
      });
    }
    res
      .status(200)
      .json({ message: 'Wallet data retrieved successfully', data: doc.data() });
  } catch (error) {
    console.error('❌ Error getting wallet data:', error);
    res
      .status(500)
      .json({ error: 'Internal server error', message: error.message });
  }
});

// Get all wallets for a user
app.get('/api/user/:userId/wallets', async (req, res) => {
  try {
    const { userId } = req.params;
    const walletsQuery = firestore
      .collection('USERS')
      .doc(userId)
      .collection('wallets');
    const snapshot = await walletsQuery.get();
    if (snapshot.empty) {
      return res
        .status(404)
        .json({ error: 'No wallets found', message: 'No wallet data found for this user' });
    }
    const wallets = [];
    snapshot.forEach((doc) => wallets.push({ id: doc.id, ...doc.data() }));
    res
      .status(200)
      .json({
        message: 'User wallets retrieved successfully',
        count: wallets.length,
        data: wallets,
      });
  } catch (error) {
    console.error('❌ Error getting user wallets:', error);
    res
      .status(500)
      .json({ error: 'Internal server error', message: error.message });
  }
});

// Query wallets w/ filters
app.get('/api/wallets', async (req, res) => {
  try {
    const {
      userId,
      limit = 10,
      offset = 0,
      chain,
      hasTokens,
      hasNFTs,
      minBalance,
    } = req.query;

    let query = firestore.collectionGroup('wallets');
    if (userId) query = query.where('userId', '==', userId);
    if (chain) query = query.where('chain', '==', chain);

    query = query.orderBy('lastUpdated', 'desc');
    if (offset > 0) query = query.offset(parseInt(offset));
    query = query.limit(parseInt(limit));

    const snapshot = await query.get();
    const wallets = [];
    snapshot.forEach((doc) => {
      const data = doc.data();
      if (hasTokens === 'true' && (!data.tokenBalances || data.tokenBalances.length === 0)) return;
      if (hasNFTs === 'true' && (!data.nftBalances || data.nftBalances.length === 0)) return;
      if (
        minBalance &&
        data.nativeBalance &&
        parseFloat(data.nativeBalance.balance) < parseFloat(minBalance)
      )
        return;
      wallets.push({ id: doc.id, ...data });
    });

    res
      .status(200)
      .json({
        message: 'Wallets retrieved successfully',
        count: wallets.length,
        limit: parseInt(limit),
        offset: parseInt(offset),
        data: wallets,
      });
  } catch (error) {
    console.error('❌ Error getting wallets with filters:', error);
    res
      .status(500)
      .json({ error: 'Internal server error', message: error.message });
  }
});

// Delete wallet doc
app.delete('/api/wallet/:userId/:address', async (req, res) => {
  try {
    const { userId, address } = req.params;
    const walletDocRef = firestore
      .collection('USERS')
      .doc(userId)
      .collection('wallets')
      .doc(address);
    await walletDocRef.delete();
    res
      .status(200)
      .json({ message: 'Wallet data deleted successfully', address, userId });
  } catch (error) {
    console.error('❌ Error deleting wallet data:', error);
    res
      .status(500)
      .json({ error: 'Internal server error', message: error.message });
  }
});

// Toggle wallet active status (Realtime DB)
app.post('/api/wallet/:userId/:address/toggle', async (req, res) => {
  try {
    const { userId, address } = req.params;
    const { choosen } = req.body;
    const walletRef = realtimeDB.ref(`USERS/${userId}/wallets/${address}/choosen`);
    await walletRef.set(choosen);
    res
      .status(200)
      .json({ message: 'Wallet status updated successfully', address, choosen });
  } catch (error) {
    console.error('❌ Error updating wallet status:', error);
    res
      .status(500)
      .json({ error: 'Internal server error', message: error.message });
  }
});

// Health check
app.get('/health', (req, res) => {
  res
    .status(200)
    .json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res
    .status(500)
    .json({ error: 'Internal server error', message: error.message });
});

/* ------------------------------------------------------------------
 * Start server
 * ----------------------------------------------------------------*/
app.listen(PORT, () => {
  console.log(`🚀 AI-DeFi-Assistant server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
