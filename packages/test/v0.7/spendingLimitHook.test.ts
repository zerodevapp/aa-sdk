// @ts-expect-error
import { beforeAll, describe, expect, test } from "bun:test"
import { signerToEcdsaValidator } from "@zerodev/ecdsa-validator"
import { toSpendingLimitHook } from "@zerodev/hooks"
import {
    type KernelAccountClient,
    type KernelSmartAccountImplementation,
    type ZeroDevPaymasterClient,
    createKernelAccount
} from "@zerodev/sdk"
import dotenv from "dotenv"
import {
    type Chain,
    type PrivateKeyAccount,
    type PublicClient,
    type Transport,
    encodeFunctionData
} from "viem"
import type { SmartAccount } from "viem/account-abstraction"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { toSudoPolicy } from "../../../plugins/permission/policies/toSudoPolicy.js"
import { toECDSASigner } from "../../../plugins/permission/signers/toECDSASigner.js"
import { toPermissionValidator } from "../../../plugins/permission/toPermissionValidator.js"
import { TEST_ERC20Abi } from "../abis/Test_ERC20Abi.js"
import {
    Test_ERC20Address,
    getEntryPoint,
    getKernelAccountClient,
    getPublicClient,
    getZeroDevPaymasterClient,
    kernelVersion,
    mintToAccount,
    validateEnvironmentVariables
} from "./utils"

dotenv.config()

const requiredEnvVars = [
    "FACTORY_ADDRESS",
    "TEST_PRIVATE_KEY",
    "RPC_URL",
    "ENTRYPOINT_ADDRESS",
    "GREETER_ADDRESS",
    "ZERODEV_PROJECT_ID",
    "ZERODEV_BUNDLER_RPC_HOST",
    "ZERODEV_PAYMASTER_RPC_HOST"
]

validateEnvironmentVariables(requiredEnvVars)

const ETHEREUM_ADDRESS_LENGTH = 42
const ETHEREUM_ADDRESS_REGEX = /^0x[0-9a-fA-F]{40}$/
const SIGNATURE_LENGTH = 174
const SIGNATURE_REGEX = /^0x[0-9a-fA-F]{172}$/
const TX_HASH_LENGTH = 66
const TX_HASH_REGEX = /^0x[0-9a-fA-F]{64}$/
const TEST_TIMEOUT = 1000000

describe("Spending Limit Hook", () => {
    let accountWithSudo: SmartAccount<KernelSmartAccountImplementation>
    let accountWithRegular: SmartAccount<KernelSmartAccountImplementation>
    let ownerAccount1: PrivateKeyAccount
    let ownerAccount2: PrivateKeyAccount
    let publicClient: PublicClient
    let kernelClientWithSudo: KernelAccountClient<
        Transport,
        Chain,
        SmartAccount<KernelSmartAccountImplementation>
    >
    let kernelClientWithRegular: KernelAccountClient<
        Transport,
        Chain,
        SmartAccount<KernelSmartAccountImplementation>
    >
    let zeroDevPaymaster: ZeroDevPaymasterClient

    beforeAll(async () => {
        // const ownerPrivateKey = process.env.TEST_PRIVATE_KEY
        // const ownerPrivateKey =
        //     "0x7630514d0cd998019c9cd4ee19a0048d6451c821ccf7927ae5e29a67104a3d92"
        const ownerPrivateKey1 = generatePrivateKey()
        const ownerPrivateKey2 = generatePrivateKey()
        publicClient = await getPublicClient()
        ownerAccount1 = privateKeyToAccount(ownerPrivateKey1)
        ownerAccount2 = privateKeyToAccount(ownerPrivateKey2)

        const ecdsaValidatorPlugin1 = await signerToEcdsaValidator(
            publicClient,
            {
                signer: ownerAccount1,
                entryPoint: getEntryPoint(),
                kernelVersion
            }
        )

        const ecdsaValidatorPlugin2 = await signerToEcdsaValidator(
            publicClient,
            {
                signer: ownerAccount2,
                entryPoint: getEntryPoint(),
                kernelVersion
            }
        )

        const ecdsaSigner = await toECDSASigner({
            signer: ownerAccount2
        })

        const sudoPolicy = await toSudoPolicy({})

        const permissoinPlugin = await toPermissionValidator(publicClient, {
            signer: ecdsaSigner,
            policies: [sudoPolicy],
            entryPoint: getEntryPoint(),
            kernelVersion
        })

        const spendingLimitHook = await toSpendingLimitHook({
            limits: [{ token: Test_ERC20Address, allowance: BigInt(4337) }]
        })

        accountWithSudo = await createKernelAccount(publicClient, {
            entryPoint: getEntryPoint(),
            plugins: {
                sudo: ecdsaValidatorPlugin1,
                hook: spendingLimitHook
            },
            kernelVersion
        })

        accountWithRegular = await createKernelAccount(publicClient, {
            entryPoint: getEntryPoint(),
            plugins: {
                sudo: ecdsaValidatorPlugin2,
                regular: permissoinPlugin,
                hook: spendingLimitHook
            },
            kernelVersion
        })

        console.log("accountWithSudo", accountWithSudo.address)
        console.log("accountWithRegular", accountWithRegular.address)

        zeroDevPaymaster = getZeroDevPaymasterClient()

        kernelClientWithSudo = await getKernelAccountClient({
            account: accountWithSudo,
            paymaster: zeroDevPaymaster
        })

        kernelClientWithRegular = await getKernelAccountClient({
            account: accountWithRegular,
            paymaster: zeroDevPaymaster
        })

        const amountToMint = 10000n
        await mintToAccount(
            publicClient,
            kernelClientWithSudo,
            kernelClientWithSudo.account.address,
            amountToMint
        )
        await mintToAccount(
            publicClient,
            kernelClientWithRegular,
            kernelClientWithRegular.account.address,
            amountToMint
        )
    })

    test(
        "Account with sudo validator can't send a ERC20 transfer transaction exceeding the allowance of spending limit hook",
        async () => {
            const amountToTransfer = 10000n
            const transferData = encodeFunctionData({
                abi: TEST_ERC20Abi,
                functionName: "transfer",
                args: [ownerAccount1.address, amountToTransfer]
            })

            await expect(
                kernelClientWithSudo.sendTransaction({
                    to: Test_ERC20Address,
                    data: transferData
                })
            ).rejects.toThrow()
        },
        TEST_TIMEOUT
    )

    test(
        "Account with sudo validator can send a ERC20 transfer transaction with a spending limit hook",
        async () => {
            const amountToTransfer = 4337n
            const transferData = encodeFunctionData({
                abi: TEST_ERC20Abi,
                functionName: "transfer",
                args: [ownerAccount1.address, amountToTransfer]
            })

            const response = await kernelClientWithSudo.sendTransaction({
                to: Test_ERC20Address,
                data: transferData
            })

            expect(response).toBeString()
            expect(response).toHaveLength(66)
            expect(response).toMatch(/^0x[0-9a-fA-F]{64}$/)
        },
        TEST_TIMEOUT
    )

    test(
        "Account with sudo validator can't send a ERC20 transfer transaction after using all allowance of spending limit hook",
        async () => {
            const amountToTransfer = 4337n
            const transferData = encodeFunctionData({
                abi: TEST_ERC20Abi,
                functionName: "transfer",
                args: [ownerAccount1.address, amountToTransfer]
            })

            await expect(
                kernelClientWithSudo.sendTransaction({
                    to: Test_ERC20Address,
                    data: transferData
                })
            ).rejects.toThrow()
        },
        TEST_TIMEOUT
    )

    test(
        "Account with regular validator can't send a ERC20 transfer transaction exceeding the allowance of spending limit hook",
        async () => {
            const amountToTransfer = 10000n
            const transferData = encodeFunctionData({
                abi: TEST_ERC20Abi,
                functionName: "transfer",
                args: [ownerAccount2.address, amountToTransfer]
            })

            await expect(
                kernelClientWithRegular.sendTransaction({
                    to: Test_ERC20Address,
                    data: transferData
                })
            ).rejects.toThrow()
        },
        TEST_TIMEOUT
    )

    test(
        "Account with regular validator can send a ERC20 transfer transaction with a spending limit hook",
        async () => {
            const amountToTransfer = 4337n
            const transferData = encodeFunctionData({
                abi: TEST_ERC20Abi,
                functionName: "transfer",
                args: [ownerAccount2.address, amountToTransfer]
            })

            const response = await kernelClientWithRegular.sendTransaction({
                to: Test_ERC20Address,
                data: transferData
            })

            expect(response).toBeString()
            expect(response).toHaveLength(66)
            expect(response).toMatch(/^0x[0-9a-fA-F]{64}$/)
        },
        TEST_TIMEOUT
    )

    test(
        "Account with regular validator can't send a ERC20 transfer transaction after using all allowance of spending limit hook",
        async () => {
            const amountToTransfer = 4337n
            const transferData = encodeFunctionData({
                abi: TEST_ERC20Abi,
                functionName: "transfer",
                args: [ownerAccount2.address, amountToTransfer]
            })

            await expect(
                kernelClientWithRegular.sendTransaction({
                    to: Test_ERC20Address,
                    data: transferData
                })
            ).rejects.toThrow()
        },
        TEST_TIMEOUT
    )
})
