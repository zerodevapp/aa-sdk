import { signerToEcdsaValidator } from "@zerodev/ecdsa-validator"
import {
    type KernelAccountClient,
    type KernelSmartAccount,
    createKernelAccount,
    createKernelAccountClient,
    createZeroDevPaymasterClient
} from "@zerodev/sdk"
import { KernelV3ExecuteAbi } from "@zerodev/sdk"
import {
    createWeightedECDSAValidator,
    getRecoveryAction
} from "@zerodev/weighted-ecdsa-validator"
import {
    type BundlerClient,
    ENTRYPOINT_ADDRESS_V07,
    createBundlerClient
} from "permissionless"
import type { Middleware } from "permissionless/actions/smartAccount"
import {
    createPimlicoBundlerClient,
    createPimlicoPaymasterClient
} from "permissionless/clients/pimlico"
import type { EntryPoint } from "permissionless/types/entrypoint"
import {
    http,
    type Address,
    type Chain,
    type Hash,
    type Hex,
    type Log,
    type PrivateKeyAccount,
    type PublicClient,
    type Transport,
    createPublicClient,
    decodeEventLog,
    encodeFunctionData,
    getAbiItem,
    toFunctionSelector,
    zeroAddress
} from "viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { polygonMumbai } from "viem/chains"
import * as allChains from "viem/chains"

import { toECDSASigner } from "../../../plugins/permission/signers/toECDSASigner"
import { toPermissionValidator } from "../../../plugins/permission/toPermissionValidator"
import type { Policy } from "../../../plugins/permission/types"
import { EntryPointAbi } from "../abis/EntryPoint"

import type { Action } from "@zerodev/sdk/types/kernel.js"
import type { SmartAccountSigner } from "permissionless/accounts/types.js"
import { deserializePermissionAccount } from "../../../plugins/permission/deserializePermissionAccount.js"
import { serializePermissionAccount } from "../../../plugins/permission/serializePermissionAccount.js"
import { TEST_ERC20Abi } from "../abis/Test_ERC20Abi.js"
import { config } from "../config.js"
import { Test_ERC20Address } from "../utils.js"

import { type RequestListener, createServer } from "http"
import type { AddressInfo } from "net"

// export const index = 43244782332432423423n
export const index = 4323343754343332434365532464445487823332432423423n
const DEFAULT_PROVIDER = "PIMLICO"
const projectId = config["v0.7"].sepolia.projectId

export const validateEnvironmentVariables = (envVars: string[]): void => {
    const unsetEnvVars = envVars.filter((envVar) => !process.env[envVar])
    if (unsetEnvVars.length > 0) {
        throw new Error(
            `The following environment variables are not set: ${unsetEnvVars.join(
                ", "
            )}`
        )
    }
}

export const findUserOperationEvent = (logs: Log[]): boolean => {
    return logs.some((log) => {
        try {
            const event = decodeEventLog({
                abi: EntryPointAbi,
                ...log
            })
            return event.eventName === "UserOperationEvent"
        } catch {
            return false
        }
    })
}

export const sleep = async (milliseconds: number): Promise<void> => {
    return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

export const waitForNonceUpdate = async (): Promise<void> => {
    return sleep(10000)
}

export const getEntryPoint = (): EntryPoint => {
    return ENTRYPOINT_ADDRESS_V07
}

export const getEcdsaKernelAccountWithRandomSigner = async (): Promise<
    KernelSmartAccount<EntryPoint>
> => {
    return getEcdsaKernelAccountWithPrivateKey(generatePrivateKey())
}

const getEcdsaKernelAccountWithPrivateKey = async <
    entryPoint extends EntryPoint
>(
    privateKey: Hex
): Promise<KernelSmartAccount<entryPoint>> => {
    if (!privateKey) {
        throw new Error("privateKey cannot be empty")
    }

    const publicClient = await getPublicClient()
    const signer = privateKeyToAccount(privateKey)
    const ecdsaValidatorPlugin = await signerToEcdsaValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: { ...signer, source: "local" as "local" | "external" }
    })

    return createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: ecdsaValidatorPlugin
        },
        index
    }) as unknown as KernelSmartAccount<entryPoint>
}

export const getKernelBundlerClient = (
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    provider?: any
): BundlerClient<EntryPoint> => {
    const chain = getTestingChain()

    return createBundlerClient({
        chain,
        transport: http(getBundlerRpc(provider)),
        entryPoint: getEntryPoint()
    })
}

export const getZeroDevERC20PaymasterClient = () => {
    if (!process.env.ZERODEV_PAYMASTER_RPC_HOST)
        throw new Error(
            "ZERODEV_PAYMASTER_RPC_HOST environment variable not set"
        )
    if (!projectId)
        throw new Error("ZERODEV_PROJECT_ID environment variable not set")

    const chain = getTestingChain()

    return createZeroDevPaymasterClient({
        chain: chain,
        transport: http(
            // currently the ERC20 paymaster must be used with StackUp
            `${process.env.ZERODEV_PAYMASTER_RPC_HOST}/${projectId}?provider=${DEFAULT_PROVIDER}`
        ),
        entryPoint: getEntryPoint()
    })
}

export const getZeroDevPaymasterClient = () => {
    if (!process.env.ZERODEV_PAYMASTER_RPC_HOST)
        throw new Error(
            "ZERODEV_PAYMASTER_RPC_HOST environment variable not set"
        )
    if (!projectId)
        throw new Error("ZERODEV_PROJECT_ID environment variable not set")

    const chain = getTestingChain()

    return createZeroDevPaymasterClient({
        chain: chain,
        transport: http(getPaymasterRpc()),
        entryPoint: getEntryPoint()
    })
}

const getPaymasterRpc = (): string => {
    const zeroDevProjectId = projectId
    const zeroDevPaymasterRpcHost = process.env.ZERODEV_PAYMASTER_RPC_HOST
    if (!zeroDevProjectId || !zeroDevPaymasterRpcHost) {
        throw new Error(
            "ZERODEV_PROJECT_ID and ZERODEV_PAYMASTER_RPC_HOST environment variables must be set"
        )
    }

    return `${zeroDevPaymasterRpcHost}/${zeroDevProjectId}?provider=${DEFAULT_PROVIDER}`
}

export const getPublicClient = async (): Promise<PublicClient> => {
    const rpcUrl = config["v0.7"].sepolia.rpcUrl
    if (!rpcUrl) {
        throw new Error("RPC_URL environment variable not set")
    }

    const publicClient = createPublicClient({
        transport: http(rpcUrl)
    })

    const chainId = await publicClient.getChainId()
    const testingChain = getTestingChain()

    if (chainId !== testingChain.id) {
        throw new Error(
            `Testing Chain ID (${testingChain.id}) not supported by RPC URL`
        )
    }

    return publicClient
}

export const getPimlicoPaymasterClient = () => {
    if (!process.env.PIMLICO_PAYMASTER_RPC_HOST)
        throw new Error(
            "PIMLICO_PAYMASTER_RPC_HOST environment variable not set"
        )

    const chain = getTestingChain()

    return createPimlicoPaymasterClient({
        chain: chain,
        transport: http(`${process.env.PIMLICO_PAYMASTER_RPC_HOST}`),
        entryPoint: getEntryPoint()
    })
}

export const getPimlicoBundlerClient = () => {
    if (!process.env.PIMLICO_BUNDLER_RPC_HOST)
        throw new Error(
            "PIMLICO_PAYMASTER_RPC_HOST environment variable not set"
        )

    const chain = getTestingChain()
    return createPimlicoBundlerClient({
        chain,
        transport: http(`${process.env.PIMLICO_BUNDLER_RPC_HOST}`),
        entryPoint: getEntryPoint()
    })
}

export const getTestingChain = (): Chain => {
    const testChainId = config["v0.7"].sepolia.chainId
    const chainId = testChainId ?? polygonMumbai.id
    const chain = Object.values(allChains).find((c) => c.id === chainId)
    if (!chain) {
        throw new Error(`Chain with id ${chainId} not found`)
    }
    return chain
}

export const getKernelAccountClient = async <entryPoint extends EntryPoint>({
    account,
    middleware
}: Middleware<entryPoint> & {
    account?: KernelSmartAccount<entryPoint>
} = {}) => {
    const chain = getTestingChain()
    const resolvedAccount =
        account ?? (await getSignerToEcdsaKernelAccount<entryPoint>())

    return createKernelAccountClient({
        account: resolvedAccount,
        chain,
        bundlerTransport: http(getBundlerRpc()),
        middleware,
        entryPoint: getEntryPoint() as entryPoint
    }) as unknown as KernelAccountClient<
        entryPoint,
        Transport,
        Chain,
        KernelSmartAccount<entryPoint>
    >
}

export const getSignerToEcdsaKernelAccount = async <
    entryPoint extends EntryPoint
>(): Promise<KernelSmartAccount<entryPoint>> => {
    const privateKey = process.env.TEST_PRIVATE_KEY as Hex
    if (!privateKey) {
        throw new Error("TEST_PRIVATE_KEY environment variable not set")
    }

    return getEcdsaKernelAccountWithPrivateKey(privateKey)
}

const getBundlerRpc = (provider?: string): string => {
    const zeroDevProjectId = projectId
    const zeroDevBundlerRpcHost = config["v0.7"].sepolia.bundlerUrl
    if (!zeroDevProjectId || !zeroDevBundlerRpcHost) {
        throw new Error(
            "ZERODEV_PROJECT_ID and ZERODEV_BUNDLER_RPC_HOST environment variables must be set"
        )
    }

    return `${zeroDevBundlerRpcHost}/${zeroDevProjectId}?provider=${DEFAULT_PROVIDER}`
}

export const waitForUserOperationTransaction = async (
    hash: Hash
): Promise<Hash> => {
    const pubicClient = await getPublicClient()
    const blockNumber = await pubicClient.getBlockNumber()
    for (let i = 0; i < 10; i++) {
        const logs = await pubicClient.getLogs({
            address: getEntryPoint(),
            event: getAbiItem({
                abi: EntryPointAbi,
                name: "UserOperationEvent"
            }),
            args: { userOpHash: hash },
            fromBlock: blockNumber - 100n
        })
        if (logs.length) {
            return logs[0].transactionHash
        }
        await new Promise((resolve) => setTimeout(resolve, 1000))
    }

    throw new Error("Failed to find transaction for User Operation")
}

// WeightedECDSAValidator utils
export const getSignersToWeightedEcdsaKernelAccount = async (): Promise<
    KernelSmartAccount<EntryPoint>
> => {
    const privateKey1 = process.env.TEST_PRIVATE_KEY as Hex
    const privateKey2 = process.env.TEST_PRIVATE_KEY2 as Hex
    if (!privateKey1 || !privateKey2) {
        throw new Error(
            "TEST_PRIVATE_KEY and TEST_PRIVATE_KEY2 environment variables must be set"
        )
    }
    const publicClient = await getPublicClient()
    const signer1 = privateKeyToAccount(privateKey1)
    const signer2 = privateKeyToAccount(privateKey2)
    const weightedECDSAPlugin = await createWeightedECDSAValidator(
        publicClient,
        {
            entryPoint: getEntryPoint(),
            config: {
                threshold: 100,
                delay: 0,
                signers: [
                    { address: signer1.address, weight: 50 },
                    { address: signer2.address, weight: 50 }
                ]
            },
            signers: [signer1, signer2]
        }
    )

    const signer = privateKeyToAccount(privateKey1)
    const ecdsaValidatorPlugin = await signerToEcdsaValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: { ...signer, source: "local" as "local" | "external" }
    })

    return await createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: ecdsaValidatorPlugin,
            regular: weightedECDSAPlugin,
            action: {
                address: zeroAddress,
                selector: toFunctionSelector(
                    getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })
                )
            }
        },
        index
    })
}

export const getRecoveryKernelAccount = async (
    deployedAccountAddress?: Address
) => {
    const privateKey1 = generatePrivateKey()
    const privateKey2 = generatePrivateKey()
    const signer1 = privateKeyToAccount(privateKey1)
    const signer2 = privateKeyToAccount(privateKey2)
    const publicClient = await getPublicClient()
    const ecdsaPlugin = await signerToEcdsaValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: signer1
    })
    const recoveryPlugin = await createWeightedECDSAValidator(publicClient, {
        entryPoint: getEntryPoint(),
        config: {
            threshold: 100,
            delay: 0,
            signers: [{ address: signer2.address, weight: 100 }]
        },
        signers: [signer2]
    })
    return await createKernelAccount(await getPublicClient(), {
        entryPoint: getEntryPoint(),
        deployedAccountAddress,
        plugins: {
            sudo: ecdsaPlugin,
            regular: recoveryPlugin,
            action: getRecoveryAction(getEntryPoint())
        },
        index
    })
}

export const getSignerToPermissionKernelAccount = async (
    policies: Policy[],
    action?: Action
): Promise<KernelSmartAccount<EntryPoint>> => {
    const privateKey1 = process.env.TEST_PRIVATE_KEY as Hex
    if (!privateKey1) {
        throw new Error(
            "TEST_PRIVATE_KEY and TEST_PRIVATE_KEY2 environment variables must be set"
        )
    }
    const publicClient = await getPublicClient()
    const signer1 = privateKeyToAccount(generatePrivateKey())
    const ecdsaModularSigner = toECDSASigner({ signer: signer1 })

    const permissionPlugin = await toPermissionValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: ecdsaModularSigner,
        policies
    })

    const signer = privateKeyToAccount(privateKey1)
    const ecdsaValidatorPlugin = await signerToEcdsaValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: { ...signer, source: "local" as "local" | "external" }
    })

    return await createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: ecdsaValidatorPlugin,
            regular: permissionPlugin,
            action: action ?? {
                address: zeroAddress,
                selector: toFunctionSelector(
                    getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })
                )
            }
        },
        index
    })
}

export const getSessionKeySignerToPermissionKernelAccount = async (
    policies: Policy[],
    sessionKeySigner: PrivateKeyAccount
): Promise<KernelSmartAccount<EntryPoint>> => {
    const privateKey1 = process.env.TEST_PRIVATE_KEY as Hex
    if (!privateKey1) {
        throw new Error(
            "TEST_PRIVATE_KEY and TEST_PRIVATE_KEY2 environment variables must be set"
        )
    }
    const publicClient = await getPublicClient()
    const ecdsaModularSigner = toECDSASigner({ signer: sessionKeySigner })

    const permissionPlugin = await toPermissionValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: ecdsaModularSigner,
        policies
    })

    const rootSigner = privateKeyToAccount(privateKey1)
    const ecdsaValidatorPlugin = await signerToEcdsaValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: { ...rootSigner, source: "local" as "local" | "external" }
    })

    return await createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: ecdsaValidatorPlugin,
            regular: permissionPlugin,
            action: {
                address: zeroAddress,
                selector: toFunctionSelector(
                    getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })
                )
            }
        },
        index
    })
}

export const getSignerToRootPermissionKernelAccount = async (
    policies: Policy[]
): Promise<KernelSmartAccount<EntryPoint>> => {
    const publicClient = await getPublicClient()
    const signer1 = privateKeyToAccount(generatePrivateKey())
    const ecdsaModularSigner = toECDSASigner({ signer: signer1 })

    const permissionPlugin = await toPermissionValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: ecdsaModularSigner,
        policies
    })

    return await createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: permissionPlugin,
            action: {
                address: zeroAddress,
                selector: toFunctionSelector(
                    getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })
                )
            }
        },
        index
    })
}

export const getSignerToRootPermissionWithSecondaryValidatorKernelAccount =
    async (policies: Policy[]): Promise<KernelSmartAccount<EntryPoint>> => {
        const publicClient = await getPublicClient()
        const signer1 = privateKeyToAccount(generatePrivateKey())
        const ecdsaModularSigner = toECDSASigner({ signer: signer1 })

        const permissionPlugin = await toPermissionValidator(publicClient, {
            entryPoint: getEntryPoint(),
            signer: ecdsaModularSigner,
            policies
        })

        const privateKey2 = generatePrivateKey()
        const signer2 = privateKeyToAccount(privateKey2)
        const ecdsaModularSigner2 = toECDSASigner({ signer: signer2 })
        const permissionSessionKeyPlugin = await toPermissionValidator(
            publicClient,
            {
                entryPoint: getEntryPoint(),
                signer: ecdsaModularSigner2,
                policies
            }
        )

        const account = await createKernelAccount(publicClient, {
            entryPoint: getEntryPoint(),
            plugins: {
                sudo: permissionPlugin,
                regular: permissionSessionKeyPlugin,
                action: {
                    address: zeroAddress,
                    selector: toFunctionSelector(
                        getAbiItem({ abi: KernelV3ExecuteAbi, name: "execute" })
                    )
                }
            },
            index
        })
        return account
    }

export async function mintToAccount(
    publicClient: PublicClient,
    ecdsaSmartAccountClient: KernelAccountClient<
        EntryPoint,
        Transport,
        Chain,
        KernelSmartAccount<EntryPoint>
    >,
    target: Address,
    amount: bigint
) {
    const balanceBefore = await publicClient.readContract({
        abi: TEST_ERC20Abi,
        address: Test_ERC20Address,
        functionName: "balanceOf",
        args: [target]
    })

    console.log("balanceBefore of account", balanceBefore)

    const amountToMint = balanceBefore > amount ? 0n : amount

    const mintData = encodeFunctionData({
        abi: TEST_ERC20Abi,
        functionName: "mint",
        args: [target, amountToMint]
    })

    if (amountToMint > 0n) {
        const mintTransactionHash =
            await ecdsaSmartAccountClient.sendTransaction({
                to: Test_ERC20Address,
                data: mintData
            })

        const balanceAfter = await publicClient.readContract({
            abi: TEST_ERC20Abi,
            address: Test_ERC20Address,
            functionName: "balanceOf",
            args: [target]
        })

        console.log("balanceAfter of account", balanceAfter)

        console.log(
            "mintTransactionHash",
            `https://sepolia.etherscan.io/tx/${mintTransactionHash}`
        )
    }
}

export function createHttpServer(
    handler: RequestListener
): Promise<{ close: () => Promise<unknown>; url: string }> {
    const server = createServer(handler)

    const closeAsync = () =>
        new Promise((resolve, reject) =>
            server.close((err) => (err ? reject(err) : resolve(undefined)))
        )

    return new Promise((resolve) => {
        server.listen(() => {
            const { port } = server.address() as AddressInfo
            resolve({ close: closeAsync, url: `http://localhost:${port}` })
        })
    })
}

export const getEcdsaKernelAccountWithRemoteSigner = async <
    entryPoint extends EntryPoint
>(
    remoteSigner: SmartAccountSigner
): Promise<KernelSmartAccount<entryPoint>> => {
    const publicClient = await getPublicClient()
    const ecdsaValidatorPlugin = await signerToEcdsaValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: remoteSigner
    })

    return createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: ecdsaValidatorPlugin
        },
        index
    }) as unknown as KernelSmartAccount<entryPoint>
}

export const getPermissionKernelAccountWithRemoteSigner = async (
    remoteSigner: SmartAccountSigner,
    policies: Policy[]
): Promise<KernelSmartAccount<EntryPoint>> => {
    const publicClient = await getPublicClient()
    const ecdsaSigner = toECDSASigner({ signer: remoteSigner })
    const permissionPlugin = await toPermissionValidator(publicClient, {
        entryPoint: getEntryPoint(),
        signer: ecdsaSigner,
        policies
    })

    return createKernelAccount(publicClient, {
        entryPoint: getEntryPoint(),
        plugins: {
            sudo: permissionPlugin
        },
        index
    })
}
