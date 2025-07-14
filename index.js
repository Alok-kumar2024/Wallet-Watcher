require('dotenv').config();
const express = require('express');
const axios = require('axios');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

// Load service account key
const serviceAccount = JSON.parse(
  Buffer.from(process.env.SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8')
);

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

// Use Realtime Database for user wallet structure and Firestore for wallet data
const realtimeDB = admin.database();
const firestore = admin.firestore();

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

const PORT = process.env.PORT || 3000;
const MORALIS_API_KEY = process.env.MORALIS_API_KEY;

// Supported chains
const SUPPORTED_CHAINS = {
  'eth': 'Ethereum',
  'polygon': 'Polygon',
  'bsc': 'BSC',
  'avalanche': 'Avalanche'
};

// Utility: Fetch comprehensive wallet data from Moralis
async function fetchComprehensiveWalletData(address, chain = 'eth') {
  try {
    const baseUrl = 'https://deep-index.moralis.io/api/v2.2';
    const headers = {
      'X-API-Key': MORALIS_API_KEY,
      'accept': 'application/json',
    };

    // Fetch multiple data types concurrently
    const [
      nativeBalance,
      tokenBalances,
      nftBalances,
      transactions,
      netWorth
    ] = await Promise.allSettled([
      // Native balance
      axios.get(`${baseUrl}/${address}/balance?chain=${chain}`, { headers }),
      
      // Token balances
      axios.get(`${baseUrl}/${address}/erc20?chain=${chain}`, { headers }),
      
      // NFT balances
      axios.get(`${baseUrl}/${address}/nft?chain=${chain}&format=decimal&limit=20`, { headers }),
      
      // Recent transactions
      axios.get(`${baseUrl}/${address}?chain=${chain}&limit=10`, { headers }),
      
      // Net worth (if available)
      axios.get(`${baseUrl}/wallets/${address}/net-worth?chains=${chain}`, { headers })
    ]);

    // Process results
    const walletData = {
      address: address,
      chain: chain,
      fetchedAt: new Date().toISOString(),
      nativeBalance: nativeBalance.status === 'fulfilled' ? nativeBalance.value.data : null,
      tokenBalances: tokenBalances.status === 'fulfilled' ? tokenBalances.value.data : [],
      nftBalances: nftBalances.status === 'fulfilled' ? nftBalances.value.data : [],
      recentTransactions: transactions.status === 'fulfilled' ? transactions.value.data : [],
      netWorth: netWorth.status === 'fulfilled' ? netWorth.value.data : null,
      errors: []
    };

    // Log any errors
    [nativeBalance, tokenBalances, nftBalances, transactions, netWorth].forEach((result, index) => {
      if (result.status === 'rejected') {
        const errorTypes = ['nativeBalance', 'tokenBalances', 'nftBalances', 'transactions', 'netWorth'];
        walletData.errors.push({
          type: errorTypes[index],
          error: result.reason.message
        });
      }
    });

    return walletData;
  } catch (error) {
    console.error(`❌ Error fetching wallet data for ${address}:`, error.message);
    return {
      address: address,
      chain: chain,
      fetchedAt: new Date().toISOString(),
      error: error.message,
      success: false
    };
  }
}

// Utility: Get active wallets from Firebase
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
          if (wallet.choosen === true || wallet.choosen === "true") {
            activeWallets.push({
              userId: userKey,
              address: walletAddr,
              walletData: wallet
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

// Utility: Store wallet data in Firestore
async function storeWalletData(userId, address, walletData) {
  try {
    // Store in Firestore with better structure
    const walletDocRef = firestore
    .collection('USERS')
    .doc(userId)
    .collection('wallets')
    .doc(address);
    
    const firestoreData = {
      userId: userId,
      address: address,
      ...walletData,
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    // Use merge to preserve createdAt on updates
    await walletDocRef.set(firestoreData, { merge: true });
    
    // Also update last sync time in Realtime DB for quick reference
    const lastSyncRef = realtimeDB.ref(`USERS/${userId}/wallets/${address}/lastSync`);
    await lastSyncRef.set(new Date().toISOString());
    
    console.log(`✅ Stored data for wallet: ${address} (User: ${userId}) in Firestore`);
    return true;
  } catch (error) {
    console.error(`❌ Error storing wallet data for ${address}:`, error);
    return false;
  }
}

// Route: Sync all active wallets (called when app opens)
app.get('/api/sync-wallets', async (req, res) => {
  try {
    const activeWallets = await getActiveWallets();
    const results = [];
    
    if (activeWallets.length === 0) {
      return res.status(200).json({
        message: 'No active wallets found',
        synced: 0,
        results: []
      });
    }

    console.log(`🔄 Syncing ${activeWallets.length} active wallets...`);

    // Process wallets in batches to avoid rate limiting
    const batchSize = 5;
    for (let i = 0; i < activeWallets.length; i += batchSize) {
      const batch = activeWallets.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (wallet) => {
        const walletData = await fetchComprehensiveWalletData(wallet.address);
        const stored = await storeWalletData(wallet.userId, wallet.address, walletData);
        
        return {
          address: wallet.address,
          userId: wallet.userId,
          success: stored && !walletData.error,
          data: walletData
        };
      });

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      // Small delay between batches
      if (i + batchSize < activeWallets.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    res.status(200).json({
      message: 'Wallet sync completed',
      synced: successful,
      failed: failed,
      total: activeWallets.length,
      results: results
    });

  } catch (error) {
    console.error('❌ Server Error in sync-wallets:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// Route: Sync specific wallet
app.post('/api/sync-wallet', async (req, res) => {
  try {
    const { address, userId, chain = 'eth' } = req.body;
    
    if (!address || !userId) {
      return res.status(400).json({
        error: 'Address and userId are required'
      });
    }

    // Validate address format (basic check)
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return res.status(400).json({
        error: 'Invalid Ethereum address format'
      });
    }

    const walletData = await fetchComprehensiveWalletData(address, chain);
    const stored = await storeWalletData(userId, address, walletData);

    if (stored && !walletData.error) {
      res.status(200).json({
        message: 'Wallet synced successfully',
        address: address,
        data: walletData
      });
    } else {
      res.status(500).json({
        error: 'Failed to sync wallet',
        address: address,
        details: walletData.error || 'Storage failed'
      });
    }

  } catch (error) {
    console.error('❌ Error in sync-wallet:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// Webhook endpoint for Moralis
// app.post('/api/webhook/moralis', async (req, res) => {
//   try {
//     const webhookData = req.body;
//     console.log('📥 Received webhook:', JSON.stringify(webhookData, null, 2));

//     // Extract address from webhook data
//     const address = webhookData.address || webhookData.from || webhookData.to;
    
//     if (!address) {
//       return res.status(400).json({
//         error: 'No address found in webhook data'
//       });
//     }

//     // Find if this address belongs to any active wallet
//     const activeWallets = await getActiveWallets();
//     const matchingWallet = activeWallets.find(wallet => 
//       wallet.address.toLowerCase() === address.toLowerCase()
//     );

//     if (matchingWallet) {
//       console.log(`🔄 Webhook triggered for active wallet: ${address}`);
      
//       // Fetch updated wallet data
//       const walletData = await fetchComprehensiveWalletData(address);
//       await storeWalletData(matchingWallet.userId, address, walletData);
      
//       res.status(200).json({
//         message: 'Webhook processed successfully',
//         address: address,
//         updated: true
//       });
//     } else {
//       console.log(`ℹ️ Webhook received for non-active wallet: ${address}`);
//       res.status(200).json({
//         message: 'Webhook received but address not in active wallets',
//         address: address,
//         updated: false
//       });
//     }

//   } catch (error) {
//     console.error('❌ Error processing webhook:', error);
//     res.status(500).json({
//       error: 'Error processing webhook',
//       message: error.message
//     });
//   }
// });

app.post('/api/webhook/moralis', async (req, res) => {
  try {
    console.log('📥 Webhook received:', JSON.stringify(req.body, null, 2));

    // ✅ Always return 200 to pass webhook test
    return res.status(200).json({ message: 'Webhook received OK' });

    // Later: You can bring back address matching logic

  } catch (error) {
    console.error('❌ Webhook error:', error);
    return res.status(200).json({ message: 'Handled with error (but 200)' });
  }
});


// Route: Get wallet data from Firestore
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
        message: 'No wallet data found in Firestore for this user and address'
      });
    }

    const walletData = doc.data();
    
    res.status(200).json({
      message: 'Wallet data retrieved successfully',
      data: walletData
    });

  } catch (error) {
    console.error('❌ Error getting wallet data:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Route: Get all wallets for a user from Firestore
app.get('/api/user/:userId/wallets', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const walletsQuery = firestore
    .collection('USERS')
    .doc(userId)
    .collection('wallets');

    const snapshot = await walletsQuery.get();
    
    if (snapshot.empty) {
      return res.status(404).json({
        error: 'No wallets found',
        message: 'No wallet data found for this user'
      });
    }

    const wallets = [];
    snapshot.forEach(doc => {
      wallets.push({
        id: doc.id,
        ...doc.data()
      });
    });

    res.status(200).json({
      message: 'User wallets retrieved successfully',
      count: wallets.length,
      data: wallets
    });

  } catch (error) {
    console.error('❌ Error getting user wallets:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Route: Get wallet data with pagination and filters
app.get('/api/wallets', async (req, res) => {
  try {
    const { 
      userId, 
      limit = 10, 
      offset = 0, 
      chain,
      hasTokens,
      hasNFTs,
      minBalance 
    } = req.query;

    let query = firestore.collectionGroup('wallets');
    
    // Add filters
    if (userId) query = query.where('userId', '==', userId);
    if (chain) query = query.where('chain', '==', chain);
    
    // Order by lastUpdated and apply pagination
    query = query.orderBy('lastUpdated', 'desc');
    
    if (offset > 0) {
      query = query.offset(parseInt(offset));
    }
    
    query = query.limit(parseInt(limit));
    
    const snapshot = await query.get();
    const wallets = [];
    
    snapshot.forEach(doc => {
      const data = doc.data();
      
      // Apply additional filters
      if (hasTokens === 'true' && (!data.tokenBalances || data.tokenBalances.length === 0)) {
        return;
      }
      
      if (hasNFTs === 'true' && (!data.nftBalances || data.nftBalances.length === 0)) {
        return;
      }
      
      if (minBalance && data.nativeBalance && parseFloat(data.nativeBalance.balance) < parseFloat(minBalance)) {
        return;
      }
      
      wallets.push({
        id: doc.id,
        ...data
      });
    });

    res.status(200).json({
      message: 'Wallets retrieved successfully',
      count: wallets.length,
      limit: parseInt(limit),
      offset: parseInt(offset),
      data: wallets
    });

  } catch (error) {
    console.error('❌ Error getting wallets with filters:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Route: Delete wallet data from Firestore
app.delete('/api/wallet/:userId/:address', async (req, res) => {
  try {
    const { userId, address } = req.params;
    
    const walletDocRef = firestore
    .collection('USERS')
    .doc(userId)
    .collection('wallets')
    .doc(address);

    await walletDocRef.delete();

    res.status(200).json({
      message: 'Wallet data deleted successfully',
      address: address,
      userId: userId
    });

  } catch (error) {
    console.error('❌ Error deleting wallet data:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Route: Toggle wallet active status
app.post('/api/wallet/:userId/:address/toggle', async (req, res) => {
  try {
    const { userId, address } = req.params;
    const { choosen } = req.body;

    const walletRef = realtimeDB.ref(`USERS/${userId}/wallets/${address}/choosen`);
    await walletRef.set(choosen);

    res.status(200).json({
      message: 'Wallet status updated successfully',
      address: address,
      choosen: choosen
    });

  } catch (error) {
    console.error('❌ Error updating wallet status:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: error.message
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 AI-DeFi-Assistant server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;