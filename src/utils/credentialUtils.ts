import { isoBase64URL } from '@simplewebauthn/server/helpers';
import logger from './logger';

/**
 * 将 ArrayBuffer 转换为 base64url 格式的字符串
 */
export const arrayBufferToBase64Url = (buffer: ArrayBuffer): string => {
    const uint8Array = new Uint8Array(buffer);
    const base64 = btoa(String.fromCharCode(...uint8Array));
    return base64ToBase64Url(base64);
};

/**
 * 将 base64 字符串转换为 base64url 格式
 */
export const base64ToBase64Url = (base64: string): string => {
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
};

/**
 * 标准化 credential ID 格式
 * 确保输出为纯 base64url 格式（无填充字符）
 */
export const normalizeCredentialId = (credentialId: any): string | undefined => {
    if (!credentialId) return undefined;
    
    try {
        // 如果是 ArrayBuffer，转换为 base64url
        if (credentialId instanceof ArrayBuffer) {
            return arrayBufferToBase64Url(credentialId);
        }
        
        // 如果是 Buffer，转换为 base64url
        if (Buffer.isBuffer(credentialId)) {
            return credentialId.toString('base64url');
        }
        
        // 如果是字符串，检查是否已经是 base64url 格式
        if (typeof credentialId === 'string') {
            // 如果已经是 base64url 格式，直接返回
            if (/^[A-Za-z0-9_-]+$/.test(credentialId)) {
                return credentialId;
            }
            
            // 尝试从 base64 转换为 base64url
            try {
                const buffer = Buffer.from(credentialId, 'base64');
                return buffer.toString('base64url');
            } catch {
                // 如果解码失败，直接转换为 base64url
                return Buffer.from(credentialId).toString('base64url');
            }
        }
        
        // 其他类型，强制转换为字符串再转 base64url
        return Buffer.from(String(credentialId)).toString('base64url');
        
    } catch (error) {
        logger.error('[CredentialUtils] normalizeCredentialId 失败:', error);
        return undefined;
    }
};

/**
 * 检查 credential ID 是否是有效的 base64url 格式
 */
export const isValidCredentialId = (credentialId: any): boolean => {
    if (!credentialId || typeof credentialId !== 'string') {
        return false;
    }
    
    // 检查是否是有效的 base64url 格式
    if (!/^[A-Za-z0-9_-]+$/.test(credentialId)) {
        return false;
    }
    
    // 尝试解码验证
    try {
        const buffer = Buffer.from(credentialId, 'base64url');
        return buffer.length > 0;
    } catch {
        return false;
    }
};

/**
 * 格式化认证响应对象
 */
export const formatAuthenticationResponse = (response: any): any => {
    if (!response) {
        throw new Error('认证响应为空');
    }

    // 确保 id 字段存在且格式正确
    const id = response.id || response.rawId;
    if (!id) {
        throw new Error('认证响应缺少 credentialId');
    }

    const normalizedId = normalizeCredentialId(id);
    if (!normalizedId) {
        throw new Error('无效的 credentialId 格式');
    }

    // 返回标准化的响应对象
    return {
        ...response,
        id: normalizedId,
        type: response.type || 'public-key'
    };
}; 