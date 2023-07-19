import {
  type SmartAccountSigner,
  type UserOperationRequest,
} from "@alchemy/aa-core";
import {
  concat,
  type Chain,
  type Hex,
  pad,
  toHex,
  type Address,
  createPublicClient,
  http,
  concatHex,
  getContract,
} from "viem";
import { KernelAccountAbi } from "../abis/KernelAccountAbi.js";
import {
  BUNDLER_URL,
  ECDSA_VALIDATOR_ADDRESS,
  ENTRYPOINT_ADDRESS,
} from "../constants.js";
import type { PaymasterAndBundlerProviders } from "../paymaster/types.js";

export enum ValidatorMode {
  sudo = "0x00000000",
  plugin = "0x00000001",
  enable = "0x00000002",
}

export interface KernelBaseValidatorParams {
  projectId: string;
  validatorAddress?: Hex;
  mode?: ValidatorMode;
  chain?: Chain;
  entryPointAddress?: Address;
  enableSignature?: Hex;
  validUntil?: number;
  validAfter?: number;
  executor?: Address;
  selector?: string;
  rpcUrl?: string;
  bundlerProvider?: PaymasterAndBundlerProviders;
}

//Kernel wallet implementation separates out validation and execution phase. It allows you to have
// custom wrapper logic for the validation phase in addition to signature of choice.
export abstract class KernelBaseValidator {
  readonly validatorAddress: Hex;
  mode: ValidatorMode;
  protected projectId: string;
  protected chain?: Chain;
  protected entryPointAddress: Address;
  protected enableSignature?: Hex;
  protected validUntil: number;
  protected validAfter: number;
  protected executor?: Address;
  protected selector?: string;
  protected rpcUrl?: string;
  protected bundlerProvider?: PaymasterAndBundlerProviders;

  constructor(params: KernelBaseValidatorParams) {
    this.projectId = params.projectId;
    this.validatorAddress = params.validatorAddress ?? ECDSA_VALIDATOR_ADDRESS;
    this.mode = params.mode ?? ValidatorMode.sudo;
    this.entryPointAddress = params.entryPointAddress ?? ENTRYPOINT_ADDRESS;
    this.enableSignature = params.enableSignature;
    this.validUntil = params.validUntil ?? 0;
    this.validAfter = params.validAfter ?? 0;
    this.executor = params.executor;
    this.selector = params.selector;
    this.chain = params.chain;
    this.rpcUrl = params.rpcUrl ?? BUNDLER_URL;
    this.bundlerProvider = params.bundlerProvider;
  }

  abstract encodeEnable(enableData: Hex): Hex;

  abstract encodeDisable(enableData: Hex): Hex;

  abstract getEnableData(): Promise<Hex>;

  abstract signMessage(message: Uint8Array | string | Hex): Promise<Hex>;

  abstract signUserOp(userOp: UserOperationRequest): Promise<Hex>;

  abstract signer(): Promise<SmartAccountSigner>;

  setEnableSignature(enableSignature: Hex) {
    this.enableSignature = enableSignature;
  }

  getAddress(): Hex {
    return this.validatorAddress;
  }

  async approveExecutor(
    kernel: string,
    selector: string,
    executor: string,
    validUntil: number,
    validAfter: number,
    validator: KernelBaseValidator
  ): Promise<string> {
    if (!this.chain) {
      throw new Error("Validator uninitialized");
    }
    const sender = kernel;
    const ownerSig = await ((await this.signer()) as any).signTypedData({
      domain: {
        name: "Kernel",
        version: "0.0.2",
        chainId: this.chain.id,
        verifyingContract: sender,
      },
      types: {
        ValidatorApproved: [
          { name: "sig", type: "bytes4" },
          { name: "validatorData", type: "uint256" },
          { name: "executor", type: "address" },
          { name: "enableData", type: "bytes" },
        ],
      },
      message: {
        sig: selector,
        validatorData: concat([
          pad(toHex(validUntil), { size: 6 }),
          pad(toHex(validAfter), { size: 6 }),
          validator.getAddress(),
        ]),
        executor,
        enableData: toHex(await validator.getEnableData()),
      },
      primaryType: "ValidatorApproved",
    });
    return ownerSig;
  }

  async resolveValidatorMode(
    userOp: UserOperationRequest
  ): Promise<ValidatorMode> {
    if (!this.chain) {
      throw new Error("Validator uninitialized");
    }
    const publicClient = createPublicClient({
      transport: http(this.rpcUrl, {
        fetchOptions: {
          headers:
            this.rpcUrl === BUNDLER_URL
              ? {
                  projectId: this.projectId,
                  bundlerProvider: this.bundlerProvider,
                }
              : {},
        },
      }),
      chain: this.chain,
    });
    const kernel = getContract({
      abi: KernelAccountAbi,
      address: userOp.sender,
      publicClient,
    });
    let mode: ValidatorMode;
    try {
      const defaultValidatorAddress = await kernel.read.getDefaultValidator();
      const executionData = await kernel.read.getExecution([
        userOp.callData.slice(0, 6) as Hex,
      ]);
      if (
        defaultValidatorAddress?.toLowerCase() ===
        this.validatorAddress.toLowerCase()
      ) {
        mode = ValidatorMode.sudo;
      } else if (
        executionData?.validator.toLowerCase() ===
        this.validatorAddress.toLowerCase()
      ) {
        mode = ValidatorMode.plugin;
      } else {
        mode = ValidatorMode.enable;
      }
    } catch (error) {
      if (this.mode === ValidatorMode.plugin) {
        mode = ValidatorMode.enable;
      } else {
        mode = this.mode;
      }
    }
    return mode;
  }

  async getSignature(userOp: UserOperationRequest): Promise<Hex> {
    const mode = await this.resolveValidatorMode(userOp);
    if (mode === ValidatorMode.sudo || mode === ValidatorMode.plugin) {
      return concatHex([this.mode, await this.signUserOp(userOp)]);
    } else {
      const enableData = await this.getEnableData();
      const enableSignature = this.enableSignature!;
      return concat([
        mode, // 4 bytes 0 - 4
        pad(toHex(this.validUntil), { size: 6 }), // 6 bytes 4 - 10
        pad(toHex(this.validAfter), { size: 6 }), // 6 bytes 10 - 16
        pad(this.validatorAddress, { size: 20 }), // 20 bytes 16 - 36
        pad(this.executor!, { size: 20 }), // 20 bytes 36 - 56
        pad(toHex(enableData.length / 2 - 1), { size: 32 }), // 32 bytes 56 - 88
        enableData, // 88 - 88 + enableData.length
        pad(toHex(enableSignature.length / 2 - 1), { size: 32 }), // 32 bytes 88 + enableData.length - 120 + enableData.length
        enableSignature, // 120 + enableData.length - 120 + enableData.length + enableSignature.length
        await this.signUserOp(userOp), // 120 + enableData.length + enableSignature.length - 120 + enableData.length + enableSignature.length + userOperation.length
      ]);
    }
  }
}
