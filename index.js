/*
 * Firestore-safe Wallet Watcher Server
 * ------------------------------------
 * Changes vs your last version:
 * 1. **Sanitize before Firestore** – removes nested arrays / undefined.
 * 2. **Shape normalization** – pick only the fields your Android data classes expect.
 * 3. **Spam/unknown symbol guard** – skip CoinGecko lookups for junk symbols to avoid 429.
 * 4. **In‑memory price cache** – reduce repeated CoinGecko calls.
 * 5. **Safer Moralis -> App field mapping** – unify nativeBalance, tokenBalances, nftBalances,
 *    recentTransactions, analytics, netWorth.
 * 6. **Batch sync throttling** – sequential batches with small pause (unchanged but documented).
 *
 * Update your Android data classes to match these shapes (you already mostly have).
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
let serviceAccount = undefined;
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

const PORT = process.env.PORT || 3000;
const MORALIS_API_KEY = process.env.MORALIS_API_KEY;
if (!MORALIS_API_KEY) {
  console.warn('⚠️  MORALIS_API_KEY missing – server will not be able to fetch chain data.');
}

/* ------------------------------------------------------------------
 * Constants & Helpers
 * ----------------------------------------------------------------*/
const SUPPORTED_CHAINS = {
  eth: { name: 'Ethereum', nativeSymbol: 'ETH', decimals: 18 },
  polygon: { name: 'Polygon', nativeSymbol: 'MATIC', decimals: 18 },
  bsc: { name: 'BSC', nativeSymbol: 'BNB', decimals: 18 },
  avalanche: { name: 'Avalanche', nativeSymbol: 'AVAX', decimals: 18 },
};

// quick upper-case lookups for spam detection
const SPAM_PATTERN = /https?:\/\/|\s{2,}|\$|visit|claim|reward|bonus|airdrop/i;
const MAX_SYMBOL_LEN = 15; // skip extremely long junk symbols

/* ------------------------------------------------------------------
 * Simple in-memory price cache (symbol -> {priceUsd, changePercent24h, logo, ts})
 * TTL default 5 min.
 * ----------------------------------------------------------------*/
const PRICE_CACHE = new Map();
const PRICE_TTL_MS = 5 * 60 * 1000;

function getCachedPrice(symbol) {
  const key = symbol.toUpperCase();
  const entry = PRICE_CACHE.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > PRICE_TTL_MS) {
    PRICE_CACHE.delete(key);
    return null;
  }
  return entry.value;
}

function setCachedPrice(symbol, value) {
  PRICE_CACHE.set(symbol.toUpperCase(), { value, ts: Date.now() });
}

/* ------------------------------------------------------------------
 * Minimal Symbol -> CoinGecko ID mapping (extend as needed)
 * We only map a few large-cap assets; everything else gets priceUsd=0.
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
 * Price Fetcher – low rate, cached, safe
 * ----------------------------------------------------------------*/
async function fetchTokenPrice(symbol) {
  if (!symbol) return { priceUsd: 0, changePercent24h: 0, logo: null };
  if (SPAM_PATTERN.test(symbol) || symbol.length > MAX_SYMBOL_LEN) {
    return { priceUsd: 0, changePercent24h: 0, logo: null };
  }

  const cached = getCachedPrice(symbol);
  if (cached) return cached;

  const id = COINGECKO_ID_MAP[symbol.toUpperCase()];
  if (!id) {
    // unknown token – skip expensive lookup
    const v = { priceUsd: 0, changePercent24h: 0, logo: null };
    setCachedPrice(symbol, v);
    return v;
  }

  try {
    const url = 'https://api.coingecko.com/api/v3/simple/price';
    const { data } = await axios.get(url, {
      params: {
        ids: id,
        vs_currencies: 'usd',
        include_24hr_change: 'true',
      },
      timeout: 10_000,
    });

    const d = data[id] || {};
    const v = {
      priceUsd: d.usd || 0,
      changePercent24h: d.usd_24h_change || 0,
      logo: null, // omit to reduce calls; you can pre-map logos if you want
    };
    setCachedPrice(symbol, v);
    return v;
  } catch (err) {
    console.error(`fetchTokenPrice error for ${symbol}:`, err.message);
    const v = { priceUsd: 0, changePercent24h: 0, logo: null };
    setCachedPrice(symbol, v); // cache failure to avoid hammering
    return v;
  }
}

/* ------------------------------------------------------------------
 * Moralis Fetch Helpers
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
 * Transform Moralis Responses -> App Model (Firestore-safe)
 * ----------------------------------------------------------------*/
function mapNativeBalance(data, chain) {
  // Moralis balance endpoint returns: { balance: "123..." }
  const chainInfo = SUPPORTED_CHAINS[chain] || SUPPORTED_CHAINS.eth;
  const bal = data?.balance ?? '0';
  return {
    balance: String(bal),
    symbol: chainInfo.nativeSymbol,
    decimals: chainInfo.decimals,
  };
}

function mapToken(token) {
  const symbol = safeSymbol(token.symbol);
  const balanceRaw = token.balance ?? '0';
  const decimals = Number.isFinite(Number(token.decimals)) ? Number(token.decimals) : 0;
  const readableBalance = decimals > 0 ? Number(balanceRaw) / 10 ** decimals : Number(balanceRaw);
  return {
    tokenAddress: token.token_address || token.address || '',
    name: token.name || symbol,
    symbol,
    balance: String(balanceRaw),
    decimals,
    readableBalance: isFinite(readableBalance) ? readableBalance : 0,
    valueUsd: token.valueUsd ?? 0, // will be enriched later
    priceUsd: token.priceUsd ?? 0,
    changePercent24h: token.changePercent24h ?? 0,
    logo: token.logo || null,
  };
}

function safeSymbol(sym) {
  if (!sym) return '';
  const cleaned = String(sym).trim();
  if (SPAM_PATTERN.test(cleaned)) return '';
  if (cleaned.length > MAX_SYMBOL_LEN) return cleaned.slice(0, MAX_SYMBOL_LEN);
  return cleaned;
}

function mapNft(nft) {
  return {
    tokenAddress: nft.token_address || nft.tokenAddress || '',
    tokenId: String(nft.token_id ?? nft.tokenId ?? ''),
    name: nft.name ?? null,
    symbol: nft.symbol ?? null,
    image: nft.normalized_metadata?.image || nft.metadata?.image || nft.image || null,
    metadata: nft.metadata ? JSON.stringify(nft.metadata).slice(0, 5_000) : null, // truncate large blobs
  };
}

function mapTx(tx, address, chain) {
  const lowerUser = address.toLowerCase();
  const from = (tx.from_address || '').toLowerCase();
  const to = (tx.to_address || '').toLowerCase();
  const isSend = from === lowerUser;
  const type = isSend ? 'send' : 'receive';

  const chainInfo = SUPPORTED_CHAINS[chain] || SUPPORTED_CHAINS.eth;

  // naive: if value>0 treat as native; else attempt ERC20 from logs
  let assetType = tx.value && tx.value !== '0' ? 'native' : 'ERC20';
  let symbol = chainInfo.nativeSymbol;
  let name = chainInfo.name;
  let logo = null;
  let amount = 0;
  let priceUsd = 0;
  let amountUsd = 0;

  if (assetType === 'native') {
    amount = Number(tx.value) / 10 ** chainInfo.decimals;
  } else {
    // attempt to inspect logs for ERC20 decimals/amount/symbol (Moralis decoded_event?)
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
          amount = val?.value ? Number(val.value) / 10 ** d : 0;
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
    logo,
    amount,
    amountUsd, // fill later w/ pricing if desired
    fromAddress: tx.from_address || '',
    toAddress: tx.to_address || '',
    timestamp: tx.block_timestamp || '',
  };
}

function computeAnalytics(tokenList) {
  let total = 0;
  for (const t of tokenList) total += Number(t.valueUsd || 0);
  const sorted = [...tokenList].sort((a, b) => (b.valueUsd || 0) - (a.valueUsd || 0));
  const top = sorted[0] || null;
  const pie = tokenList.map((t) => ({
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
 * SANITIZER – Firestore-safe deep clone (no nested arrays)
 * ----------------------------------------------------------------*/
function sanitizeForFirestore(value) {
  if (Array.isArray(value)) {
    // Drop nested arrays & sanitize items
    const out = [];
    for (const item of value) {
      if (Array.isArray(item)) continue; // skip nested arrays entirely
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
      moralisGet(`/${address}/nft`, { ...params, format: 'decimal', limit: 20 }),
      moralisGet(`/${address}`, { ...params, limit: 10 }),
      moralisGet(`/wallets/${address}/net-worth`, { chains: chain }),
    ]);

    // Native balance
    const nativeBalance =
      nativeRes.status === 'fulfilled' ? mapNativeBalance(nativeRes.value, chain) : null;

    // Tokens (raw from Moralis may contain many extra fields)
    const rawTokens = tokenRes.status === 'fulfilled' ? tokenRes.value : [];
    const tokenList = Array.isArray(rawTokens)
      ? rawTokens
      : Array.isArray(rawTokens?.result)
      ? rawTokens.result
      : [];

    const enrichedTokens = [];
    for (const t of tokenList) {
      const mapped = mapToken(t);
      // Price enrich only for a small, safe set
      const priceData = await fetchTokenPrice(mapped.symbol);
      mapped.priceUsd = priceData.priceUsd;
      mapped.changePercent24h = priceData.changePercent24h;
      mapped.logo = priceData.logo;
      mapped.valueUsd = mapped.readableBalance * mapped.priceUsd;
      enrichedTokens.push(mapped);
    }

    // NFTs
    const rawNfts = nftRes.status === 'fulfilled' ? nftRes.value : [];
    const nftArr = Array.isArray(rawNfts)
      ? rawNfts
      : Array.isArray(rawNfts?.result)
      ? rawNfts.result
      : [];
    const nftBalances = nftArr.map(mapNft);

    // Transactions
    const rawTxs = txRes.status === 'fulfilled' ? txRes.value?.result || [] : [];
    const recentTransactions = rawTxs.map((tx) => mapTx(tx, address, chain));

    // Net Worth: Moralis response shape may vary; try to read.
    let netWorth = null;
    if (netRes.status === 'fulfilled') {
      const v = netRes.value;
      const total = v?.total_networth_usd ?? v?.net_worth_usd ?? null;
      if (total != null) {
        netWorth = { totalNetworthUsd: Number(total) };
      }
    }
    if (!netWorth) {
      // fallback compute from tokens + ignore native for now (or add if priced)
      let tokenTotal = 0;
      for (const t of enrichedTokens) tokenTotal += Number(t.valueUsd || 0);
      netWorth = { totalNetworthUsd: tokenTotal };
    }

    // Analytics
    const analytics = computeAnalytics(enrichedTokens);

    const walletData = {
      address,
      chain,
      fetchedAt: new Date().toISOString(),
      nativeBalance,
      tokenBalances: enrichedTokens,
      nftBalances,
      recentTransactions,
      netWorth,
      analytics,
      errors: [],
    };

    // record individual fetch errors (optional)
    const errorTypes = ['nativeBalance', 'tokenBalances', 'nftBalances', 'transactions', 'netWorth'];
    [nativeRes, tokenRes, nftRes, txRes, netRes].forEach((r, i) => {
      if (r.status === 'rejected') {
        walletData.errors.push({ type: errorTypes[i], error: r.reason?.message || String(r.reason) });
      }
    });

    return walletData;
  } catch (error) {
    console.error(`❌ Error fetching wallet data for ${address}:`, error.message);
    return {
      address,
      chain,
      fetchedAt: new Date().toISOString(),
      error: error.message,
      success: false,
      nativeBalance: null,
      tokenBalances: [],
      nftBalances: [],
      recentTransactions: [],
      netWorth: { totalNetworthUsd: 0 },
      analytics: { totalTokenValueUsd: 0, topToken: { name: '', valueUsd: 0, sharePercent: '0.00' }, tokenDistribution: [] },
      errors: [{ type: 'general', error: error.message }],
    };
  }
}

/* ------------------------------------------------------------------
 * Active Wallets – from Realtime DB (unchanged)
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
            activeWallets.push({ userId: userKey, address: walletAddr, walletData: wallet });
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
    const walletDocRef = firestore.collection('USERS').doc(userId).collection('wallets').doc(address);

    // Firestore-safe clone
    const clean = sanitizeForFirestore(walletData);

    const firestoreData = {
      userId,
      address,
      ...clean,
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    await walletDocRef.set(firestoreData, { merge: true });

    // update lastSync in Realtime DB
    const lastSyncRef = realtimeDB.ref(`USERS/${userId}/wallets/${address}/lastSync`);
    await lastSyncRef.set(new Date().toISOString());

    console.log(`✅ Stored data for wallet: ${address} (User: ${userId}) in Firestore`);
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
      return res.status(200).json({ message: 'No active wallets found', synced: 0, results: [] });
    }

    console.log(`🔄 Syncing ${activeWallets.length} active wallets...`);

    const batchSize = 2; // lower to reduce external API pressure
    for (let i = 0; i < activeWallets.length; i += batchSize) {
      const batch = activeWallets.slice(i, i + batchSize);
      for (const wallet of batch) {
        const walletData = await fetchComprehensiveWalletData(wallet.address);
        const stored = await storeWalletData(wallet.userId, wallet.address, walletData);
        results.push({ address: wallet.address, userId: wallet.userId, success: stored && !walletData.error, data: walletData });
      }
      // short pause between batches
      if (i + batchSize < activeWallets.length) {
        await new Promise((r) => setTimeout(r, 750));
      }
    }

    const successful = results.filter((r) => r.success).length;
    const failed = results.filter((r) => !r.success).length;

    res.status(200).json({ message: 'Wallet sync completed', synced: successful, failed, total: activeWallets.length, results });
  } catch (error) {
    console.error('❌ Server Error in sync-wallets:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
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
      res.status(200).json({ message: 'Wallet synced successfully', address, data: walletData });
    } else {
      res.status(500).json({ error: 'Failed to sync wallet', address, details: walletData.error || 'Storage failed' });
    }
  } catch (error) {
    console.error('❌ Error in sync-wallet:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// Webhook from Moralis
app.post('/api/webhook/moralis', async (req, res) => {
  try {
    const webhookData = req.body;
    console.log('📥 Received webhook:', JSON.stringify(webhookData, null, 2));

    // Try to locate an address in payload
    const address = webhookData.address || webhookData.from || webhookData.to;
    if (!address) {
      return res.status(400).json({ error: 'No address found in webhook data' });
    }

    const activeWallets = await getActiveWallets();
    const matchingWallet = activeWallets.find((w) => w.address.toLowerCase() === address.toLowerCase());

    if (matchingWallet) {
      console.log(`🔄 Webhook triggered sync for ${address}`);
      const walletData = await fetchComprehensiveWalletData(address);
      await storeWalletData(matchingWallet.userId, address, walletData);
      res.status(200).json({ message: 'Webhook processed successfully', address, updated: true });
    } else {
      console.log(`ℹ️ Webhook received for non-active wallet: ${address}`);
      res.status(200).json({ message: 'Webhook received but address not in active wallets', address, updated: false });
    }
  } catch (error) {
    console.error('❌ Error processing webhook:', error);
    res.status(500).json({ error: 'Error processing webhook', message: error.message });
  }
});

// Get wallet doc
app.get('/api/wallet/:userId/:address', async (req, res) => {
  try {
    const { userId, address } = req.params;
    const walletDocRef = firestore.collection('USERS').doc(userId).collection('wallets').doc(address);
    const doc = await walletDocRef.get();
    if (!doc.exists) {
      return res.status(404).json({ error: 'Wallet data not found', message: 'No wallet data found in Firestore for this user and address' });
    }
    res.status(200).json({ message: 'Wallet data retrieved successfully', data: doc.data() });
  } catch (error) {
    console.error('❌ Error getting wallet data:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// Get all wallets for a user
app.get('/api/user/:userId/wallets', async (req, res) => {
  try {
    const { userId } = req.params;
    const walletsQuery = firestore.collection('USERS').doc(userId).collection('wallets');
    const snapshot = await walletsQuery.get();
    if (snapshot.empty) {
      return res.status(404).json({ error: 'No wallets found', message: 'No wallet data found for this user' });
    }
    const wallets = [];
    snapshot.forEach((doc) => wallets.push({ id: doc.id, ...doc.data() }));
    res.status(200).json({ message: 'User wallets retrieved successfully', count: wallets.length, data: wallets });
  } catch (error) {
    console.error('❌ Error getting user wallets:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// Query wallets w/ filters
app.get('/api/wallets', async (req, res) => {
  try {
    const { userId, limit = 10, offset = 0, chain, hasTokens, hasNFTs, minBalance } = req.query;

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
      if (minBalance && data.nativeBalance && parseFloat(data.nativeBalance.balance) < parseFloat(minBalance)) return;
      wallets.push({ id: doc.id, ...data });
    });

    res.status(200).json({ message: 'Wallets retrieved successfully', count: wallets.length, limit: parseInt(limit), offset: parseInt(offset), data: wallets });
  } catch (error) {
    console.error('❌ Error getting wallets with filters:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// Delete wallet doc
app.delete('/api/wallet/:userId/:address', async (req, res) => {
  try {
    const { userId, address } = req.params;
    const walletDocRef = firestore.collection('USERS').doc(userId).collection('wallets').doc(address);
    await walletDocRef.delete();
    res.status(200).json({ message: 'Wallet data deleted successfully', address, userId });
  } catch (error) {
    console.error('❌ Error deleting wallet data:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// Toggle wallet active status (Realtime DB)
app.post('/api/wallet/:userId/:address/toggle', async (req, res) => {
  try {
    const { userId, address } = req.params;
    const { choosen } = req.body;
    const walletRef = realtimeDB.ref(`USERS/${userId}/wallets/${address}/choosen`);
    await walletRef.set(choosen);
    res.status(200).json({ message: 'Wallet status updated successfully', address, choosen });
  } catch (error) {
    console.error('❌ Error updating wallet status:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error', message: error.message });
});

/* ------------------------------------------------------------------
 * Start server
 * ----------------------------------------------------------------*/
app.listen(PORT, () => {
  console.log(`🚀 AI-DeFi-Assistant server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
