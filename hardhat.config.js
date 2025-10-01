// hardhat.config.js — ESM for Hardhat v3
import "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default {
  solidity: {
    version: "0.8.24", // or 0.8.26/0.8.28 to match your pragma
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    hardhat: {
      type: "edr-simulated", // ✅ explicitly declare the built-in simulator
    },
    // Example external network (optional):
    // sepolia: {
    //   type: "http",
    //   url: process.env.SEPOLIA_RPC_URL,
    //   accounts: process.env.SEPOLIA_PRIVATE_KEY ? [process.env.SEPOLIA_PRIVATE_KEY] : [],
    // },
  },
};
