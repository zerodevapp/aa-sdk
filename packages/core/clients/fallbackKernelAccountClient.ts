import type { EntryPoint } from "permissionless/types"
import type { Chain, Transport } from "viem"
import type { KernelSmartAccount } from "../accounts/index.js"
import type { KernelAccountClient } from "./kernelAccountClient.js"

export const createFallbackKernelAccountClient = <
    TEntryPoint extends EntryPoint,
    TTransport extends Transport,
    TChain extends Chain | undefined,
    TSmartAccount extends KernelSmartAccount<TEntryPoint> | undefined
>(
    clients: Array<
        KernelAccountClient<TEntryPoint, TTransport, TChain, TSmartAccount>
    >,
    onError?: (error: Error, clientUrl: string) => Promise<void>
): KernelAccountClient<TEntryPoint, TTransport, TChain, TSmartAccount> => {
    // Map to store methods extended at runtime.
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    const extendedMethods = new Map<PropertyKey, any>()

    // Function to create a fallback method for a given property.
    // This method will try each client in sequence until one succeeds or all fail.
    function createFallbackMethod(prop: PropertyKey) {
        // biome-ignore lint/suspicious/noExplicitAny: <explanation>
        return async (...args: any[]) => {
            console.log(`Executing fallback method for ${String(prop)}`)
            for (let i = 0; i < clients.length; i++) {
                try {
                    const method = Reflect.get(clients[i], prop)
                    if (typeof method === "function") {
                        return await method(...args)
                    }
                } catch (error) {
                    console.error(
                        `Action ${String(prop)} failed with client ${
                            clients[i].transport.url
                        }, trying next if available.`
                    )
                    console.log(error)
                    // Call the error handler if provided.
                    if (onError !== undefined) {
                        await onError(error as Error, clients[i].transport.url)
                    }
                    if (i === clients.length - 1) {
                        throw error
                    }
                }
            }
        }
    }

    console.log("Creating proxyClient")

    const proxyClient = new Proxy(clients[0], {
        get(_target, prop, receiver) {
            if (prop === "extend") {
                // biome-ignore lint/suspicious/noExplicitAny: <explanation>
                return (fn: any) => {
                    const modifications = fn(proxyClient)
                    for (const [key, modification] of Object.entries(
                        modifications
                    )) {
                        if (typeof modification === "function") {
                            // biome-ignore lint/suspicious/noExplicitAny: <explanation>
                            ;(proxyClient as any)[key] = async (
                                ...args: any[]
                            ) => {
                                return await modification(...args)
                            }
                        } else {
                            console.error(
                                `Expected a function for modification of ${key}, but received type ${typeof modification}`
                            )
                        }
                    }
                    return proxyClient // Consider whether to return a new instance
                }
            }

            // Return an extended method if it exists.
            if (extendedMethods.has(prop)) {
                // console.log("Using extended method", prop)
                return extendedMethods.get(prop)
            }

            const value = Reflect.get(_target, prop, receiver)
            if (typeof value === "function") {
                return createFallbackMethod(prop)
            }
            return value
        }
    })

    console.log("Proxy client created")

    // Return the proxy client that now supports fallback and extension.
    return proxyClient
}
