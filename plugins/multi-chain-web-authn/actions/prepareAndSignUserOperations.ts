import {
    AccountNotFoundError,
    type Action,
    type KernelSmartAccountImplementation,
    KernelV3AccountAbi,
    getEncodedPluginsData,
    isPluginInitialized
} from "@zerodev/sdk"
import { MerkleTree } from "merkletreejs"
import {
    type Chain,
    type Client,
    type Hex,
    type Transport,
    concatHex,
    encodeAbiParameters,
    getAbiItem,
    hashMessage,
    hashTypedData,
    keccak256,
    toFunctionSelector,
    zeroAddress
} from "viem"
import {
    type PrepareUserOperationParameters,
    type PrepareUserOperationReturnType,
    type SendUserOperationParameters,
    type SmartAccount,
    type UserOperation,
    getUserOperationHash,
    prepareUserOperation
} from "viem/account-abstraction"
import { parseAccount } from "viem/accounts"
import { getAction } from "viem/utils"

export type PrepareAndSignUserOperationsParameters<
    account extends SmartAccount | undefined = SmartAccount | undefined,
    accountOverride extends SmartAccount | undefined = SmartAccount | undefined,
    calls extends readonly unknown[] = readonly unknown[]
> = SendUserOperationParameters<account, accountOverride, calls> & {
    chainId: number
}

export type SignUserOperationsReturnType = PrepareUserOperationReturnType[]

export async function prepareAndSignUserOperations<
    account extends SmartAccount | undefined,
    chain extends Chain | undefined,
    accountOverride extends SmartAccount | undefined = undefined,
    calls extends readonly unknown[] = readonly unknown[]
>(
    clients: Client<Transport, chain, account>[],
    args_: PrepareAndSignUserOperationsParameters<
        account,
        accountOverride,
        calls
    >[]
): Promise<SignUserOperationsReturnType> {
    if (clients.length < 2 && args_.length < 2) {
        throw new Error("Should send more than 1 user operation")
    }
    if (clients.length !== args_.length) {
        throw new Error("Number of clients and user operations do not match")
    }
    for (let i = 0; i < clients.length; i++) {
        const client = clients[i]
        const arg = args_[i]

        if (client.chain === undefined) {
            throw new Error("client.chain is undefined, please provide a chain")
        }

        if (client.chain.id !== arg.chainId) {
            throw new Error(
                `Chain ID mismatch at index ${i}: client.chainId (${client.chain.id}) !== args_.chainId (${arg.chainId})`
            )
        }
    }

    const args = args_ as PrepareAndSignUserOperationsParameters[]
    const accounts_ = args.map(
        (arg, index) => arg.account ?? clients[index].account
    )
    if (
        !accounts_.every(
            (account): account is SmartAccount => account !== undefined
        )
    ) {
        throw new AccountNotFoundError()
    }

    const accounts = accounts_.map(
        (account) =>
            parseAccount(
                account
            ) as SmartAccount<KernelSmartAccountImplementation>
    )

    const _userOperations = args.map(({ chainId, ...userOp }) => userOp)

    const action: Action = {
        selector: toFunctionSelector(
            getAbiItem({ abi: KernelV3AccountAbi, name: "execute" })
        ),
        address: zeroAddress
    }

    const account = accounts[0]

    // check if regular validator exists
    if (account.kernelPluginManager.regularValidator) {
        const isPluginEnabledPerChains = await Promise.all(
            accounts.map(
                async (account, index) =>
                    (await account.kernelPluginManager.isEnabled(
                        account.address,
                        action.selector
                    )) ||
                    (await isPluginInitialized(
                        clients[index],
                        account.address,
                        account.kernelPluginManager.address
                    ))
            )
        )

        const allEnabled = isPluginEnabledPerChains.every((enabled) => enabled)
        const noneEnabled = isPluginEnabledPerChains.every(
            (enabled) => !enabled
        )

        if (!allEnabled && !noneEnabled) {
            throw new Error(
                "Plugins must be either all enabled or all disabled across chains."
            )
        }
        // if regular validators are not enabled, encode with enable signatures
        if (noneEnabled) {
            const dummySignatures = await Promise.all(
                accounts.map(async (account, index) => {
                    return account.kernelPluginManager.regularValidator?.getStubSignature(
                        _userOperations[index] as UserOperation
                    )
                })
            )

            for (const signature of dummySignatures) {
                if (signature === undefined) {
                    throw new Error("Dummy signatures are undefined")
                }
            }

            const pluginEnableTypedDatas = await Promise.all(
                accounts.map(async (account) => {
                    return account.kernelPluginManager.getPluginsEnableTypedData(
                        account.address
                    )
                })
            )

            const leaves = pluginEnableTypedDatas.map((typedData) => {
                return hashTypedData(typedData)
            })

            const merkleTree = new MerkleTree(leaves, keccak256, {
                sortPairs: true
            })

            const merkleRoot = merkleTree.getHexRoot() as Hex
            const toEthSignedMessageHash = hashMessage({ raw: merkleRoot })

            const passkeySig = await account.kernelPluginManager.signMessage({
                message: {
                    raw: toEthSignedMessageHash
                }
            })

            if (!passkeySig) {
                throw new Error(
                    "No passkeySig, check if the sudo validator is multi-chain-web-authn-validator"
                )
            }

            const enableSigs = accounts.map((_, index) => {
                const merkleProof = merkleTree.getHexProof(
                    leaves[index]
                ) as Hex[]
                const encodedMerkleProof = encodeAbiParameters(
                    [{ name: "proof", type: "bytes32[]" }],
                    [merkleProof]
                )
                const merkleData = concatHex([merkleRoot, encodedMerkleProof])
                return encodeAbiParameters(
                    [
                        {
                            name: "merkleData",
                            type: "bytes"
                        },
                        {
                            name: "signature",
                            type: "bytes"
                        }
                    ],
                    [merkleData, passkeySig]
                )
            })

            const encodedDummySignatures = await Promise.all(
                accounts.map(async (account, index) => {
                    return getEncodedPluginsData({
                        enableSignature: enableSigs[index],
                        userOpSignature: dummySignatures[index] as Hex,
                        action,
                        enableData:
                            await account.kernelPluginManager.getEnableData(
                                account.address
                            )
                    })
                })
            )

            _userOperations.forEach((userOperation, index) => {
                userOperation.signature = encodedDummySignatures[index]
            })

            const userOperations = await Promise.all(
                _userOperations.map(async (_userOperation, index) => {
                    return await getAction(
                        clients[index],
                        prepareUserOperation,
                        "prepareUserOperation"
                    )(_userOperation as PrepareUserOperationParameters)
                })
            )

            const encodedSignatures = await Promise.all(
                userOperations.map(async (userOperation, index) => {
                    return await getEncodedPluginsData({
                        enableSignature: enableSigs[index],
                        userOpSignature: await accounts[
                            index
                        ].kernelPluginManager.signUserOperationWithActiveValidator(
                            userOperation as UserOperation
                        ),
                        action,
                        enableData: await accounts[
                            index
                        ].kernelPluginManager.getEnableData(account.address)
                    })
                })
            )

            userOperations.forEach((userOperation, index) => {
                userOperation.signature = encodedSignatures[index]
            })

            return userOperations as SignUserOperationsReturnType
        }
        // if regular validators are enabled, use signUserOperationWithActiveValidator directly
        if (allEnabled) {
            const userOperations = await Promise.all(
                _userOperations.map(async (_userOperation, index) => {
                    return await getAction(
                        clients[index],
                        prepareUserOperation,
                        "prepareUserOperation"
                    )(_userOperation as PrepareUserOperationParameters)
                })
            )

            const signatures = await Promise.all(
                userOperations.map((userOperation, index) =>
                    accounts[
                        index
                    ].kernelPluginManager.signUserOperationWithActiveValidator(
                        userOperation as UserOperation
                    )
                )
            )

            userOperations.forEach((userOperation, index) => {
                userOperation.signature = signatures[index]
            })

            return userOperations as SignUserOperationsReturnType
        }
    }
    // If regular validators do not exist, sign with multi-chain-ecdsa-validator
    const userOperations = await Promise.all(
        _userOperations.map(async (_userOperation, index) => {
            return await getAction(
                clients[index],
                prepareUserOperation,
                "prepareUserOperation"
            )(_userOperation as PrepareUserOperationParameters)
        })
    )

    const userOpHashes = userOperations.map((userOp, index) => {
        return getUserOperationHash({
            userOperation: {
                ...userOp,
                signature: "0x"
            } as UserOperation,
            entryPointAddress: account.entryPoint.address,
            entryPointVersion: account.entryPoint.version,
            chainId: args_[index].chainId
        })
    })

    const merkleTree = new MerkleTree(userOpHashes, keccak256, {
        sortPairs: true
    })

    const merkleRoot = merkleTree.getHexRoot() as Hex
    const toEthSignedMessageHash = hashMessage({ raw: merkleRoot })

    const passkeySig = await account.kernelPluginManager.signMessage({
        message: {
            raw: toEthSignedMessageHash
        }
    })

    const encodeMerkleDataWithSig = (userOpHash: Hex) => {
        const merkleProof = merkleTree.getHexProof(userOpHash) as Hex[]

        const encodedMerkleProof = encodeAbiParameters(
            [{ name: "proof", type: "bytes32[]" }],
            [merkleProof]
        )
        const merkleData = concatHex([merkleRoot, encodedMerkleProof])
        return encodeAbiParameters(
            [
                {
                    name: "merkleData",
                    type: "bytes"
                },
                {
                    name: "signature",
                    type: "bytes"
                }
            ],
            [merkleData, passkeySig]
        )
    }

    const signedMultiUserOps = userOperations.map((userOp, index) => {
        return {
            ...userOp,
            signature: encodeMerkleDataWithSig(userOpHashes[index])
        }
    })

    return signedMultiUserOps as SignUserOperationsReturnType
}
