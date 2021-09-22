package com.johanpmeert;

/**
 * The goal of this support Class is to be have a series of RPC calls that will work with all of the following coin flavours/nodes:
 * - Bitcoin BTC (Bitcoind or bitcoin-QT), version 0.19.1
 * - Bitcoin Cash BCH (Bitcoin ABC), version 0.21.4
 * - Bitcoin BSV, version 1.0.3
 * - Bitcoin Gold BTG, version 0.17.1
 * Any differences in the RPC implementation between the nodes will be resolved by the class.
 * <p>
 * Change the values of the Enum CoinData for access to all your nodes
 * <p>
 * Supported RPC calls at this time:
 * - ValidateBitcoinAddress
 * - ValidateBitcoinAddressDetails
 * - GetBlockHash
 * - GetBlock
 * - GetTransactionsFromBlock
 * - GetRawTransaction
 * - GetBlockCount
 * - GetNetworkInfo
 * <p>
 * *********************************************************
 * LICENSE INFORMATION
 * <p>
 * This software is released under APACHE LICENSE V2.0
 * Please read details on http://www.apache.org/licenses/
 * **********************************************************
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.math.BigDecimal;
import java.net.*;

public class JpmBitcoinRpcClient {

    /**
     * Enum type used to store all connection information about the nodes, easy to edit and expand if necessary
     */
    public enum CoinData {
        BTC("BTC", "jswemmelbtc", "ZEHUGANovjdw7jJUuZZr1L2sa", "192.168.2.16", 8332),
        BCH("BCH", "johan", "g4RP7QAncx4vr", "192.168.2.126", 8332),
        BSV("BSV", "johan", "uFJpoKDJAxFo", "192.168.2.17", 8332),
        BTG("BTG", "johan", "pci8VNgiMoyC", "192.168.2.10", 8332),
        EMPTY("not_a_valid_coin", "", "", "", 0);

        public final String Label;
        public final String RPC_USER;
        public final String RPC_PASSWORD;
        public final String RPC_ADDRESS;
        public final int RPC_PORT;

        CoinData(String label, String rpcuser, String rpcpassword, String rpcaddress, int rpcport) {
            this.Label = label;
            this.RPC_USER = rpcuser;
            this.RPC_PASSWORD = rpcpassword;
            this.RPC_ADDRESS = rpcaddress;
            this.RPC_PORT = rpcport;
        }
    }

    private final String PROTOCOL = "http";
    private HttpURLConnection connection = null;
    private URL rpcUrl;
    private final CoinData typeOfBitcoin;

    /**
     * Creates an instance connection to the node
     * @param typeofbitcoin an instance of the Enum to see which node type you want
     */
    public JpmBitcoinRpcClient(CoinData typeofbitcoin) {
        this.typeOfBitcoin = typeofbitcoin;
        class CustomAuthenticator extends Authenticator {
            protected PasswordAuthentication getPasswordAuthentication() {
                final String rpcUser = typeOfBitcoin.RPC_USER;
                final String rpcPassword = typeOfBitcoin.RPC_PASSWORD;
                return new PasswordAuthentication(rpcUser, rpcPassword.toCharArray());
            }
        }
        Authenticator.setDefault(new CustomAuthenticator());
        try {
            rpcUrl = new URL(PROTOCOL + "://" + typeOfBitcoin.RPC_ADDRESS + ":" + typeOfBitcoin.RPC_PORT + "/");
        } catch (MalformedURLException e) {
            System.out.println("Node " + typeOfBitcoin.Label + " is offline");
            e.printStackTrace();
        }
    }

    /**
     * Returns true if the given bitcoin address is considered valid by the node
     * @param bitcoinAddress
     * @return boolean
     */
    public boolean ValidateBitcoinAddress(String bitcoinAddress) {
        final String POST_PARAMS = "{\"method\":\"validateaddress\",\"params\":[\"" + bitcoinAddress + "\"]}";
        try {
            connection = (HttpURLConnection) rpcUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) return false;
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String jsonResponse = brin.readLine();
            brin.close();
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            ValidateAddress validateAddress = gson.fromJson(jsonResponse.trim(), ValidateAddress.class);
            return validateAddress.result.isvalid;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return false;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /**
     * Return the full response of a node in regards to the validity of a bitcoin address
     * @param bitcoinAddress
     * @return ValidateAddress
     */
    public ValidateAddress ValidateBitcoinAddressDetails(String bitcoinAddress) {
        final String POST_PARAMS = "{\"method\":\"validateaddress\",\"params\":[\"" + bitcoinAddress + "\"]}";
        try {
            connection = (HttpURLConnection) rpcUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) return null;
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String jsonResponse = brin.readLine();
            brin.close();
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            ValidateAddress validateAddress = gson.fromJson(jsonResponse.trim(), ValidateAddress.class);
            return validateAddress;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    public class ValidateAddress {
        Result result;
        String error;
        String id;
    }

    public class Result {
        boolean isvalid;
        String address;
        String scriptPubKey;
        boolean ismine;             // only in BSV
        boolean iswatchonly;        // only in BSV
        boolean isscript;           // only in BSV and BCH
        boolean iswitness;          // only in BTC and BTG
    }

    /**
     * Returns the String blockhash of the given int blocknr
     * @param blockNr
     * @return String
     */
    public String GetBlockHash(int blockNr) {
        final String POST_PARAMS = "{\"method\":\"getblockhash\",\"params\":[" + blockNr + "]}";
        try {
            connection = (HttpURLConnection) rpcUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) return "Http error";
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String jsonResponse = brin.readLine();
            brin.close();
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            BlockHash blockHash = gson.fromJson(jsonResponse.trim(), BlockHash.class);
            return blockHash.result;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return "IO error";
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private class BlockHash {
        String result;
        String error;
        String id;
    }

    /**
     * Return a full block given the blockhash, block is with verbosity 2 so contains full details of all transactions
     * Attention the return data can get VERY large (several hundred megabytes and into the Gigabyte range) especially with BSV nodes
     * Please make sure your heap size can swallow this, recommended is 6Gb heap size
     * For BSV nodes, you may need up to 12Gb heap size to be able to import a block
     * @param blockHash
     * @return Block
     */
    public Block GetBlock(String blockHash) {
        final String POST_PARAMS = "{\"method\":\"getblock\",\"params\":[\"" + blockHash + "\",2]}";
        try {
            connection = (HttpURLConnection) rpcUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) return null;
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            Block block = gson.fromJson(brin, Block.class);
            brin.close();
            return block;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /**
     * This class contains all the data for a complete block. Some variables may not be used by all node types
     */
    public class Block {
        public MiddleBlock result;
        public String error;
        public String id;
    }

    public class MiddleBlock {
        public String hash;
        public int confirmations;
        public int strippedsize;
        public int size;
        public int weight;
        public int height;
        public int version;
        public String versionhex;
        public String merkleroot;
        public Trans[] tx;
        public long time;
        public long mediantime;
        public long nonceUint32;
        public String nonce;
        public String solution;
        public String bits;
        public BigDecimal difficulty;
        public String chainwork;
        public int nTx;
        public String previousblockhash;
        public String nextblockhash;
    }

    public class Trans {
        public String txid;
        public String hash;
        public int version;
        public int size;
        public int vsize;
        public int weight;
        public int locktime;
        public Vin[] vin;
        public Vout[] vout;
        public String hex;
    }

    public class Vin {
        public String coinbase;
        public String txid;
        public int vout;
        public ScriptSig scriptSig;
        public long sequence;
    }

    public class Vout {
        public BigDecimal value;
        public int n;
        public Scriptpubkey scriptPubKey;
    }

    public class ScriptSig {
        public String asm;
        public String hex;
    }

    public class Scriptpubkey {
        public String asm;
        public String hex;
        public int reqSigs;
        public String type;
        public String[] addresses;
    }

    /**
     * Returns the verbosity 1 details of a block (input is a blockhash, not a blocknumber)
     * You can use this data to get the transaction details per transaction with GetRawTransaction
     * @param blockHash
     * @return
     */
    public TransactionsInBlock GetTransactionsFromBlock(String blockHash) {
        final String POST_PARAMS = "{\"method\":\"getblock\",\"params\":[\"" + blockHash + "\",1]}";
        try {
            connection = (HttpURLConnection) rpcUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) return null;
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder builder = new StringBuilder();
            String extra;
            // Same remarks as with GetBlock are valid here even though this JSON response is much smaller
            do {
                extra = brin.readLine();
                if (extra != null) builder.append(extra);
            } while (extra != null);
            brin.close();
            String jsonResponse = builder.toString().trim();
            // System.out.println(jsonResponse);
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            TransactionsInBlock trib = gson.fromJson(jsonResponse, TransactionsInBlock.class);
            return trib;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    public class TransactionsInBlock {
        public ResultBlock result;
        public String error;
        public String id;
    }

    public class ResultBlock {
        public String[] tx;
        public String hash;
        public int confirmations;
        public int size;
        public int height;
        public int version;
        public String versionHex;
        public String merkleroot;
        public int num_tx;
        public long time;
        public long mediantime;
        public long nonce;
        public String bits;
        public BigDecimal difficulty;
        public String chainwork;
        public String previousblockhash;
        public String nextblockhash;
    }

    /**
     * Gets the full transaction details of a specific txId
     * @param txId
     * @return
     */
    public SingleTransaction GetRawTransaction(String txId) {
        final String POST_PARAMS = "{\"method\":\"getrawtransaction\",\"params\":[\"" + txId + "\",2]}";
        try {
            connection = (HttpURLConnection) rpcUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) return null;
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder builder = new StringBuilder();
            String extra;
            // Same remarks as with GetBlock are valid here even though this JSON response is much smaller
            do {
                extra = brin.readLine();
                if (extra != null) builder.append(extra);
            } while (extra != null);
            brin.close();
            String jsonResponse = builder.toString().trim();
            // System.out.println(jsonResponse);
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            SingleTransaction trib = gson.fromJson(jsonResponse, SingleTransaction.class);
            return trib;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            System.out.println("connection lost");
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    public class SingleTransaction {
        public TxResult result;
        public String error;
        public String id;
    }

    public class TxResult {
        public String txid;
        public String hash;
        public int version;
        public int size;
        public long locktime;
        public Vin[] vin;
        public Vout[] vout;
        public String blockhash;
        public int confirmations;
        public long time;
        public long blocktime;
        public int blockheight;
        public String hex;
    }

    /**
     * Returns the actual blockcount the node is at
     * @return int
     */
    public int GetBlockCount() {
        final String POST_PARAMS = "{\"method\":\"getblockcount\"}";
        try {
            connection = (HttpURLConnection) rpcUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) return -1;
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String jsonResponse = brin.readLine();
            brin.close();
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            BlockCount bC = gson.fromJson(jsonResponse.trim(), BlockCount.class);
            return bC.result;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return -1;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    public class BlockCount {
        public int result;
        public boolean error;
        public boolean id;
    }

    /**
     * Returns the information about the node
     * @return networkinfo
     */
    public NetworkInfo GetNetworkInfo() {
        final String POST_PARAMS = "{\"method\":\"getnetworkinfo\"}";
        try {
            connection = (HttpURLConnection) rpcUrl.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            OutputStream os = connection.getOutputStream();
            os.write(POST_PARAMS.getBytes());
            os.flush();
            os.close();
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) return null;
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String jsonResponse = brin.readLine();
            brin.close();
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            NetworkInfo nwinfo = gson.fromJson(jsonResponse.trim(), NetworkInfo.class);
            return nwinfo;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    public class NetworkInfo {
        public NetworkInfoResult result;
        public boolean error;
        public boolean id;
    }

    public class NetworkInfoResult {
        public int version;
        public String subversion;
        public int protocolversion;
        public String localservices;
        public String[] localservicesnames;
        public boolean localrelay;
        public int timeoffset;
        public int connections;
        public boolean networkactive;
        public Networks[] networks;
        public BigDecimal relayfee;
        public BigDecimal incrementalfee;
        public LocalAddresses[] localaddresses;
        public String warnings;
    }

    public class Networks {
        public String name;
        public boolean limited;
        public boolean reachable;
        public String proxy;
        public boolean proxy_randomize_credentials;
    }

    public class LocalAddresses {
        public String address;
        public int port;
        public int score;
    }

    /**
     * Independant method to get the coin balance from my private server through JSON
     * @param checkAddress coin address string
     * @param coinData type of coin (BTC, BCH, BSV or BTG) using an enum
     * @return BigDecimal value of balance
     */
    public static BigDecimal GetCoinValueFromJPM(String checkAddress, CoinData coinData) {
        HttpURLConnection connection = null;
        BufferedReader reader = null;
        try {
            URL url = new URL("http://johanpmeert.ddns.net:8100/balance/" + coinData.Label + "=" + checkAddress);
            connection = (HttpURLConnection) url.openConnection();
            connection.connect();
            BufferedReader brin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String jsonResponse = brin.readLine();
            brin.close();
            Gson gson = new GsonBuilder().setLenient().create();  // take care of "malformed JSON" error
            JPMbalance jpmBalance = gson.fromJson(jsonResponse.trim(), JPMbalance.class);
            return jpmBalance.balance;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return BigDecimal.ZERO;
    }

    public class JPMbalance {
        public BigDecimal balance;
        public CoinData currency;
        public int blockheight;
        public String errortype;
    }

    public static byte[] hexStringToByteArray(String hex) {
        hex = hex.length() % 2 != 0 ? "0" + hex : hex;
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}

