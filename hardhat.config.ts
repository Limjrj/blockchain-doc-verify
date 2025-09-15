// hardhat.config.ts (ESM + TypeScript, Hardhat v3)
import { config as dotenvConfig } from "dotenv";
dotenvConfig();

import "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import type { HardhatUserConfig } from "hardhat/config";

const config: HardhatUserConfig = {
  solidity: {
    // Use the compiler that matches your pragma.
    // Our contract is ^0.8.24; 0.8.26 or 0.8.28 also work under ^0.8.24.
    version: "0.8.26",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    hardhat: {}, // in-memory local chain for tests
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "",          // set in .env
      accounts: process.env.SEPOLIA_PRIVATE_KEY
        ? [process.env.SEPOLIA_PRIVATE_KEY]
        : [],
    },
  },
};

export default config;
