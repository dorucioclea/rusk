import type { Readable } from "svelte/store";
import type { Wallet } from "@dusk-network/dusk-wallet-js";

type TransactionsStoreContent = { transactions: Transaction[] };

type TransactionsStore = Readable<TransactionsStoreContent>;

type WalletStoreContent = {
  balance: {
    maximum: number;
    value: number;
  };
  currentAddress: string;
  error: Error | null;
  initialized: boolean;
  addresses: string[];
  isSyncing: boolean;
};

type WalletStoreServices = {
  abortSync: () => void;

  clearLocalData: () => Promise<void>;

  clearLocalDataAndInit: (
    wallet: Wallet,
    syncFromBlock?: number
  ) => Promise<void>;

  getCurrentBlockHeight: () => Promise<number>;

  getStakeInfo: () => Promise<any> & ReturnType<Wallet["stakeInfo"]>;

  // The return type apparently is not in a promise here
  getTransactionsHistory: () => Promise<ReturnType<Wallet["history"]>>;

  init: (wallet: Wallet, syncFromBlock?: number) => Promise<void>;

  reset: () => void;

  setCurrentAddress: (address: string) => Promise<void>;

  stake: (
    amount: number,
    gasPrice: number,
    gasLimit: number
  ) => Promise<any> & ReturnType<Wallet["stake"]>;

  sync: (from?: number) => Promise<void>;

  transfer: (
    to: string,
    amount: number,
    gasPrice: number,
    gasLimit: number
  ) => Promise<any> & ReturnType<Wallet["transfer"]>;

  unstake: (
    gasPrice: number,
    gasLimit: number
  ) => Promise<any> & ReturnType<Wallet["unstake"]>;

  withdrawReward: (
    gasPrice: number,
    gasLimit: number
  ) => Promise<any> & ReturnType<Wallet["withdrawReward"]>;
};

type WalletStore = Readable<WalletStoreContent> & WalletStoreServices;

type SettingsStore = {
  currency: string;
  darkMode: boolean;
  dashboardTransactionLimit: number;
  gasLimit: number;
  gasPrice: number;
  hideStakingNotice: boolean;
  language: string;
  minAllowedStake: number;
  network: string;
  userId: string;
};

type GasStoreContent = {
  gasLimitLower: number;
  gasLimitUpper: number;
  gasPriceLower: number;
};

type GasStore = Readable<GasStoreContent>;
