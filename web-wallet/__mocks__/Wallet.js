class Wallet {
  constructor(seed, gasLimit = 2900000000, gasPrice = 1) {
    this.gasLimit = gasLimit;
    this.gasPrice = gasPrice;
    this.seed = seed;
    this.wasm = {};
  }

  static get networkBlockHeight() {
    return Promise.resolve(0);
  }

  gasLimit;
  gasPrice;
  seed;
  wasm;

  async history() {}
  async getBalance() {}
  async getPsks() {}
  async stake() {}
  async stakeAllow() {}
  async stakeInfo() {}
  async reset() {}
  async sync() {}
  async transfer() {}
  async unstake() {}
  async withdrawReward() {}
}

export default Wallet;
