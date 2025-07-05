import {
    generateRegistrationOptions,
    generateAuthenticationOptions,
    verifyRegistrationResponse,
    verifyAuthenticationResponse,
    VerifiedRegistrationResponse,
    VerifiedAuthenticationResponse
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { User, UserStorage } from '../utils/userStorage';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import logger from '../utils/logger';
import { env } from '../config/env';
import { normalizeCredentialId, isValidCredentialId, formatAuthenticationResponse } from '../utils/credentialUtils';

// 认证器模型
interface Authenticator {
    id: string;
    name: string;
    credentialID: string;
    credentialPublicKey: string;
    counter: number;
    createdAt: string;
    // Passkey相关字段
    isPasskey?: boolean;
    credentialDeviceType?: string;
    credentialBackedUp?: boolean;
}

// 获取 RP ID（依赖域名）
const getRpId = () => {
    return env.RP_ID;
};

// 获取 RP 原点
const getRpOrigin = () => {
    return env.RP_ORIGIN;
};

// 自动修复用户历史passkey credentialID为base64url字符串，并详细日志
async function fixUserPasskeyCredentialIDs(user: User) {
    if (!user) {
        logger.warn('[Passkey自愈] 用户对象为空');
        return;
    }
    
    if (!Array.isArray(user.passkeyCredentials)) {
        logger.warn('[Passkey自愈] passkeyCredentials不是数组，重置为空数组', { 
            userId: user.id, 
            type: typeof user.passkeyCredentials,
            value: user.passkeyCredentials 
        });
        user.passkeyCredentials = [];
        await UserStorage.updateUser(user.id, { passkeyCredentials: [] });
        return;
    }
    
    let changed = false;
    
    for (let i = 0; i < user.passkeyCredentials.length; i++) {
        const cred = user.passkeyCredentials[i];
        if (!cred || typeof cred !== 'object') {
            logger.warn('[Passkey自愈] 发现无效的credential对象，剔除', { 
                userId: user.id, 
                index: i, 
                cred 
            });
            user.passkeyCredentials[i] = null as any;
            changed = true;
            continue;
        }
        
        const original = cred.credentialID;
        const fixed = normalizeCredentialId(original);
        
        if (!fixed) {
            logger.warn('[Passkey自愈] credentialID无法修复，剔除', {
                userId: user.id,
                original
            });
            user.passkeyCredentials[i] = null as any;
            changed = true;
            continue;
        }
        
        if (fixed !== original) {
            cred.credentialID = fixed;
            changed = true;
            logger.info('[Passkey自愈] credentialID已修复', {
                userId: user.id,
                original,
                fixed
            });
        }
    }
    
    // 剔除所有无效credential
    const before = user.passkeyCredentials.length;
    user.passkeyCredentials = user.passkeyCredentials.filter(c => 
        c && 
        typeof c === 'object' && 
        typeof c.credentialID === 'string' && 
        isValidCredentialId(c.credentialID)
    );
    const after = user.passkeyCredentials.length;
    
    if (before !== after) {
        logger.warn('[Passkey自愈] 剔除无效credentialID', { userId: user.id, before, after });
        changed = true;
    }
    
    if (changed) {
        await UserStorage.updateUser(user.id, { passkeyCredentials: user.passkeyCredentials });
        logger.info('[Passkey自愈] 已更新用户passkeyCredentials', { userId: user.id });
    }
}

export class PasskeyService {
    // 获取用户的认证器列表
    public static async getCredentials(userId: string): Promise<Authenticator[]> {
        const user = await UserStorage.getUserById(userId);
        if (user) {
            await fixUserPasskeyCredentialIDs(user);
        }
        if (!user || !user.passkeyCredentials) {
            return [];
        }
        return user.passkeyCredentials;
    }

    // 生成注册选项
    public static async generateRegistrationOptions(user: User, credentialName: string) {
        await fixUserPasskeyCredentialIDs(user);
        if (!user) {
            throw new Error('generateRegistrationOptions: user 为空');
        }
        if (!user.id) {
            throw new Error('generateRegistrationOptions: user.id 为空');
        }
        if (!user.username) {
            throw new Error('generateRegistrationOptions: user.username 为空');
        }
        const userAuthenticators = user.passkeyCredentials || [];
        let options;
        try {
            options = await generateRegistrationOptions({
                rpName: 'Happy TTS',
                rpID: getRpId(),
                userID: Buffer.from(user.id),
                userName: user.username,
                attestationType: 'none',
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    // 使用新的residentKey选项替代requireResidentKey
                    residentKey: 'required',
                    userVerification: 'preferred' // 改为preferred以支持无生物识别传感器的设备
                },
                excludeCredentials: userAuthenticators.map(authenticator => ({
                    id: authenticator.credentialID,
                    type: 'public-key',
                    transports: ['internal']
                } as any))
            });
        } catch (err) {
            logger.error('[PasskeyService] generateRegistrationOptions 调用底层库异常:', err);
            throw new Error('generateRegistrationOptions: 调用底层库异常: ' + (err instanceof Error ? err.message : String(err)));
        }
        if (!options) {
            throw new Error('generateRegistrationOptions: options 为 undefined');
        }
        if (!options.challenge) {
            throw new Error('generateRegistrationOptions: options.challenge 为 undefined');
        }
        // 存储挑战到用户记录
        await UserStorage.updateUser(user.id, {
            pendingChallenge: options.challenge
        });
        return options;
    }

    // 验证注册
    public static async verifyRegistration(
        user: User,
        response: any,
        credentialName: string,
        requestOrigin?: string
    ): Promise<VerifiedRegistrationResponse> {
        await fixUserPasskeyCredentialIDs(user);
        
        // 格式化响应对象
        const formattedResponse = formatAuthenticationResponse(response);
        
        try {
            const verification = await verifyRegistrationResponse({
                response: formattedResponse,
                expectedChallenge: user.pendingChallenge || '',
                expectedOrigin: requestOrigin || getRpOrigin(),
                expectedRPID: getRpId(),
                requireUserVerification: false // 改为 false 以支持无生物识别传感器的设备
            });

            const { verified, registrationInfo } = verification;

            if (verified && registrationInfo) {
                const { credentialPublicKey, credentialID, counter } = registrationInfo as any;

                const normalizedCredentialId = normalizeCredentialId(credentialID);
                if (!normalizedCredentialId) {
                    throw new Error('注册失败：无效的 credentialID');
                }

                const existingCredential = user.passkeyCredentials?.find(
                    cred => cred.credentialID === normalizedCredentialId
                );

                if (existingCredential) {
                    throw new Error('此 Passkey 已注册');
                }

                const newAuthenticator: Authenticator = {
                    id: normalizedCredentialId,
                    name: credentialName,
                    credentialID: normalizedCredentialId,
                    credentialPublicKey: credentialPublicKey.toString('base64url'),
                    counter,
                    createdAt: new Date().toISOString(),
                    isPasskey: true,
                    credentialDeviceType: (registrationInfo as any).credentialDeviceType,
                    credentialBackedUp: (registrationInfo as any).credentialBackedUp
                };

                if (!user.passkeyCredentials) {
                    user.passkeyCredentials = [];
                }

                user.passkeyCredentials.push(newAuthenticator);
                await UserStorage.updateUser(user.id, {
                    passkeyCredentials: user.passkeyCredentials,
                    pendingChallenge: ''
                });

                return verification;
            }

            throw new Error('注册验证失败');
        } catch (error) {
            logger.error('[PasskeyService] verifyRegistration 失败:', error);
            throw error;
        }
    }

    // 生成认证选项
    public static async generateAuthenticationOptions(user: User) {
        if (!user) {
            throw new Error('用户对象为空');
        }
        
        await fixUserPasskeyCredentialIDs(user);
        const userAuthenticators = user.passkeyCredentials || [];
        
        if (userAuthenticators.length === 0) {
            throw new Error('用户没有注册的认证器');
        }
        
        // 确保所有credentialID都是有效的字符串
        const validCredentials = userAuthenticators.filter(cred => 
            cred && 
            typeof cred === 'object' && 
            typeof cred.credentialID === 'string' && 
            /^[A-Za-z0-9_-]+$/.test(cred.credentialID) && 
            cred.credentialID.length > 0
        );
        
        if (validCredentials.length === 0) {
            logger.error('[Passkey] 用户无有效Passkey凭证', { userId: user.id });
            throw new Error('所有Passkey已失效，请重新注册');
        }
        
        try {
            // 最终安全检查：确保所有credentialID都是有效的base64url字符串
            const finalValidCredentials = validCredentials.filter(cred => {
                const isValid = typeof cred.credentialID === 'string' && 
                               /^[A-Za-z0-9_-]+$/.test(cred.credentialID) && 
                               cred.credentialID.length > 0;
                
                if (!isValid) {
                    logger.warn('[Passkey] 发现无效credentialID，跳过', {
                        userId: user.id,
                        credentialID: cred.credentialID,
                        type: typeof cred.credentialID
                    });
                }
                
                return isValid;
            });
            
            if (finalValidCredentials.length === 0) {
                logger.error('[Passkey] 最终检查后无有效凭证', { userId: user.id });
                throw new Error('所有Passkey已失效，请重新注册');
            }
            
            logger.info('[Passkey] 准备生成认证选项', {
                userId: user.id,
                validCredentialsCount: finalValidCredentials.length,
                credentialIDs: finalValidCredentials.map(c => c.credentialID.substring(0, 10) + '...'),
                allowCredentials: finalValidCredentials.map(authenticator => ({
                    id: authenticator.credentialID.substring(0, 20) + '...',
                    type: 'public-key',
                    transports: ['internal']
                }))
            });
            
            // 确保allowCredentials格式正确
            const allowCredentials = finalValidCredentials.map(authenticator => {
                logger.info('[Passkey] 处理认证器:', {
                    userId: user.id,
                    credentialID: authenticator.credentialID.substring(0, 20) + '...',
                    credentialIDLength: authenticator.credentialID.length,
                    isValidBase64Url: /^[A-Za-z0-9_-]+$/.test(authenticator.credentialID)
                });
                
                return {
                    id: authenticator.credentialID,
                    transports: ['internal'] as any
                };
            });
            
            logger.info('[Passkey] 生成的allowCredentials:', {
                userId: user.id,
                count: allowCredentials.length,
                credentials: allowCredentials.map(cred => ({
                    id: cred.id.substring(0, 20) + '...',
                    transports: cred.transports,
                    fullId: cred.id
                })),
                fullAllowCredentials: JSON.stringify(allowCredentials, null, 2)
            });
            
            const options = await generateAuthenticationOptions({
                rpID: getRpId(),
                allowCredentials,
                userVerification: 'preferred' // 改为preferred以支持无生物识别传感器的设备
            });
            
            logger.info('[Passkey] generateAuthenticationOptions返回结果:', {
                userId: user.id,
                hasOptions: !!options,
                optionsKeys: Object.keys(options || {}),
                challenge: options?.challenge?.substring(0, 20) + '...',
                allowCredentialsCount: options?.allowCredentials?.length || 0,
                fullOptions: JSON.stringify(options, null, 2)
            });
            
            // 存储挑战到用户记录
            await UserStorage.updateUser(user.id, {
                pendingChallenge: options.challenge
            });
            
            return options;
        } catch (err: any) {
            // 检查input.replace is not a function等类型错误，强制修复所有credentialID
            if (err && err.message && err.message.includes('replace is not a function')) {
                logger.warn('[Passkey自愈] 捕获到input.replace类型错误，强制修复所有credentialID并重试', {
                    userId: user.id,
                    error: err.message
                });
                
                // 再次尝试修复
                await fixUserPasskeyCredentialIDs(user);
                
                // 重新获取过滤后的 credentials
                const retryValidCredentials = user.passkeyCredentials?.filter(c => 
                    c && 
                    typeof c === 'object' && 
                    typeof c.credentialID === 'string' && 
                    /^[A-Za-z0-9_-]+$/.test(c.credentialID) && 
                    c.credentialID.length > 0
                );
                
                if (!retryValidCredentials || retryValidCredentials.length === 0) {
                    logger.error('[Passkey自愈] 修复后无可用Passkey，需重新注册', { userId: user.id });
                    throw new Error('所有Passkey已失效，请重新注册');
                }
                
                // 最终安全检查：确保所有credentialID都是有效的base64url字符串
                const finalRetryCredentials = retryValidCredentials.filter(cred => {
                    const isValid = typeof cred.credentialID === 'string' && 
                                   /^[A-Za-z0-9_-]+$/.test(cred.credentialID) && 
                                   cred.credentialID.length > 0;
                    
                    if (!isValid) {
                        logger.warn('[Passkey自愈] 重试时发现无效credentialID，跳过', {
                            userId: user.id,
                            credentialID: cred.credentialID,
                            type: typeof cred.credentialID
                        });
                    }
                    
                    return isValid;
                });
                
                if (finalRetryCredentials.length === 0) {
                    logger.error('[Passkey自愈] 重试时最终检查后无有效凭证', { userId: user.id });
                    throw new Error('所有Passkey已失效，请重新注册');
                }
                
                logger.info('[Passkey自愈] 重试生成认证选项', {
                    userId: user.id,
                    validCredentialsCount: finalRetryCredentials.length,
                    credentialIDs: finalRetryCredentials.map(c => c.credentialID.substring(0, 10) + '...')
                });
                
                // 再次尝试
                const options = await generateAuthenticationOptions({
                    rpID: getRpId(),
                    allowCredentials: finalRetryCredentials.map(authenticator => ({
                        id: authenticator.credentialID,
                        transports: ['internal']
                    })),
                    userVerification: 'preferred' // 改为preferred以支持无生物识别传感器的设备
                });
                
                await UserStorage.updateUser(user.id, {
                    pendingChallenge: options.challenge
                });
                
                return options;
            }
            
            // 记录其他类型的错误
            logger.error('[Passkey] generateAuthenticationOptions 失败', {
                userId: user.id,
                error: err.message,
                stack: err.stack
            });
            
            throw err;
        }
    }

    // 验证认证
    public static async verifyAuthentication(
        user: User,
        response: any,
        requestOrigin?: string
    ): Promise<VerifiedAuthenticationResponse> {
        await fixUserPasskeyCredentialIDs(user);
        
        // 格式化响应对象
        const formattedResponse = formatAuthenticationResponse(response);
        
        if (!formattedResponse.id) {
            throw new Error('认证失败：缺少 credentialID');
        }

        const normalizedCredentialId = normalizeCredentialId(formattedResponse.id);
        if (!normalizedCredentialId) {
            throw new Error('认证失败：无效的 credentialID');
        }

        const authenticator = user.passkeyCredentials?.find(
            cred => cred.credentialID === normalizedCredentialId
        );

        if (!authenticator) {
            throw new Error('未找到匹配的 Passkey');
        }

        try {
            const verification = await verifyAuthenticationResponse({
                response: formattedResponse,
                expectedChallenge: user.pendingChallenge || '',
                expectedOrigin: requestOrigin || getRpOrigin(),
                expectedRPID: getRpId(),
                requireUserVerification: false, // 改为 false 以支持无生物识别传感器的设备
                credential: {
                    id: authenticator.credentialID,
                    publicKey: Buffer.from(authenticator.credentialPublicKey, 'base64url'),
                    counter: authenticator.counter
                }
            });

            const { verified, authenticationInfo } = verification;

            if (verified) {
                // 更新计数器
                authenticator.counter = authenticationInfo.newCounter;
                await UserStorage.updateUser(user.id, {
                    passkeyCredentials: user.passkeyCredentials,
                    pendingChallenge: ''
                });

                return verification;
            }

            throw new Error('认证验证失败');
        } catch (error) {
            logger.error('[PasskeyService] verifyAuthentication 失败:', error);
            throw error;
        }
    }

    // 删除认证器
    public static async removeCredential(userId: string, credentialId: string): Promise<void> {
        const user = await UserStorage.getUserById(userId);
        if (user) {
            await fixUserPasskeyCredentialIDs(user);
        }
        if (!user || !user.passkeyCredentials) {
            throw new Error('用户不存在或没有认证器');
        }

        const updatedCredentials = user.passkeyCredentials.filter(
            auth => auth.id !== credentialId
        );

        if (updatedCredentials.length === user.passkeyCredentials.length) {
            throw new Error('找不到指定的认证器');
        }

        // 更新用户记录
        await UserStorage.updateUser(userId, {
            passkeyCredentials: updatedCredentials,
            passkeyEnabled: updatedCredentials.length > 0
        });
    }

    // 生成访问令牌
    public static async generateToken(user: User): Promise<string> {
        return jwt.sign(
            { userId: user.id, username: user.username },
            config.jwtSecret,
            { expiresIn: '24h' }
        );
    }
} 