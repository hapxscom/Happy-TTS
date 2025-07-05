import { useState, useCallback, useEffect } from 'react';
import { 
    startRegistration, 
    startAuthentication, 
    browserSupportsWebAuthn, 
    browserSupportsWebAuthnAutofill,
    type RegistrationResponseJSON,
    type AuthenticationResponseJSON
} from '@simplewebauthn/browser';
import { passkeyApi, Authenticator } from '../api/passkey';
import { useToast } from './useToast';
import { useAuth } from './useAuth';
import { CredentialIdModal } from '../components/ui/CredentialIdModal';
import { DebugInfoModal } from '../components/DebugInfoModal';
import { formatAuthenticationResponse, normalizeCredentialId } from '../utils/credentialUtils';
import { SimpleUser } from '../types/auth';

interface UsePasskeyReturn {
    credentials: Authenticator[];
    isLoading: boolean;
    isSupported: boolean;
    hasAutofillSupport: boolean;
    supportChecked: boolean;
    loadCredentials: () => Promise<void>;
    registerAuthenticator: (name: string) => Promise<void>;
    removeAuthenticator: (id: string) => Promise<void>;
    authenticateWithPasskey: (username: string) => Promise<boolean>;
}

export const usePasskey = (): UsePasskeyReturn & {
    showModal: boolean;
    setShowModal: React.Dispatch<React.SetStateAction<boolean>>;
    currentCredentialId: string;
    setCurrentCredentialId: React.Dispatch<React.SetStateAction<string>>;
    showDebugModal: boolean;
    setShowDebugModal: React.Dispatch<React.SetStateAction<boolean>>;
    debugInfos: any[];
    addDebugInfo: (info: any) => void;
} => {
    const [credentials, setCredentials] = useState<Authenticator[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [isSupported, setIsSupported] = useState(false);
    const [hasAutofillSupport, setHasAutofillSupport] = useState(false);
    const [supportChecked, setSupportChecked] = useState(false);
    const { showToast } = useToast();
    const { loginWithToken } = useAuth();

    // 弹窗状态
    const [showModal, setShowModal] = useState(false);
    const [currentCredentialId, setCurrentCredentialId] = useState('');
    const [showDebugModal, setShowDebugModal] = useState(false);
    const [debugInfos, setDebugInfos] = useState<any[]>([]);

    // 检查浏览器支持
    useEffect(() => {
        const checkSupport = async () => {
            const webauthnSupport = browserSupportsWebAuthn();
            const autofillSupport = await browserSupportsWebAuthnAutofill();
            setIsSupported(webauthnSupport);
            setHasAutofillSupport(autofillSupport);
            setSupportChecked(true);
            addDebugInfo({
                action: '检查浏览器支持',
                webauthnSupport,
                autofillSupport,
                userAgent: navigator.userAgent,
                timestamp: new Date().toISOString()
            });
        };
        checkSupport();
    }, []);

    // 添加调试信息
    const addDebugInfo = useCallback((info: any) => {
        setDebugInfos(prev => [...prev, {
            ...info,
            timestamp: info.timestamp || new Date().toISOString()
        }]);
    }, []);

    // 加载凭证列表
    const loadCredentials = useCallback(async () => {
        if (!isSupported) {
            showToast('您的浏览器不支持 Passkey', 'error');
            return;
        }

        try {
            setIsLoading(true);
            const response = await passkeyApi.getCredentials();
            setCredentials(response.data);
            
            addDebugInfo({
                action: '加载凭证列表',
                credentialsCount: response.data.length,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            if (error instanceof Error && error.message === 'Unauthorized') {
                showToast('登录已过期，请重新登录', 'error');
            } else {
                showToast('加载 Passkey 凭证失败', 'error');
            }
            
            addDebugInfo({
                action: '加载凭证失败',
                error: error instanceof Error ? error.message : String(error),
                timestamp: new Date().toISOString()
            });
        } finally {
            setIsLoading(false);
        }
    }, [isSupported, showToast, addDebugInfo]);

    // 注册新的认证器
    const registerAuthenticator = useCallback(async (credentialName: string) => {
        if (!isSupported) {
            showToast('您的浏览器不支持 Passkey', 'error');
            return;
        }

        setIsLoading(true);
        
        try {
            // 获取注册选项
            const optionsResponse = await passkeyApi.startRegistration(credentialName);
            if (!optionsResponse.data?.options) {
                throw new Error('注册失败: 服务器未返回有效的注册选项');
            }

            addDebugInfo({
                action: '开始注册',
                credentialName,
                hasOptions: true,
                rpId: optionsResponse.data.options.rp?.id,
                timeout: optionsResponse.data.options.timeout,
                timestamp: new Date().toISOString()
            });

            try {
                // 调用浏览器API进行注册
                const attResp = await startRegistration({ 
                    optionsJSON: optionsResponse.data.options,
                });

                // 标准化 credentialId
                if (attResp.id) {
                    setCurrentCredentialId(attResp.id);
                    setShowModal(true);
                    addDebugInfo({
                        action: '注册成功',
                        credentialId: attResp.id,
                        type: attResp.type,
                        timestamp: new Date().toISOString()
                    });
                }

                // 完成注册
                const verificationResponse = await passkeyApi.finishRegistration(credentialName, attResp);
                
                if (!verificationResponse.success) {
                    throw new Error('服务器验证失败: ' + verificationResponse.error);
                }

                showToast('Passkey 注册成功', 'success');
                await loadCredentials();
                
            } catch (error: any) {
                if (error?.name === 'NotAllowedError') {
                    throw new Error('用户取消了操作');
                } else if (error?.name === 'InvalidStateError') {
                    throw new Error('该认证器可能已经注册过了');
                } else {
                    throw error;
                }
            }
            
        } catch (error: any) {
            let errorMessage = '注册 Passkey 失败';
            if (error?.message) {
                errorMessage = error.message;
            }
            
            addDebugInfo({
                action: '注册失败',
                error: errorMessage,
                errorDetails: error instanceof Error ? error.stack : String(error),
                timestamp: new Date().toISOString()
            });
            
            showToast(errorMessage, 'error');
        } finally {
            setIsLoading(false);
        }
    }, [isSupported, loadCredentials, showToast, addDebugInfo]);

    // 认证
    const authenticateWithPasskey = useCallback(async (username: string): Promise<boolean> => {
        if (!isSupported) {
            showToast('您的浏览器不支持 Passkey', 'error');
            return false;
        }

        try {
            setIsLoading(true);
            
            addDebugInfo({
                action: '开始Passkey认证',
                username,
                timestamp: new Date().toISOString()
            });
            
            // 获取认证选项
            const optionsResponse = await passkeyApi.startAuthentication(username);
            if (!optionsResponse.data?.options) {
                throw new Error('认证选项获取失败：服务器未返回有效选项');
            }

            const options = optionsResponse.data.options;
            addDebugInfo({
                action: 'Passkey认证选项',
                rpId: options.rpId,
                timeout: options.timeout,
                userVerification: options.userVerification,
                allowCredentials: options.allowCredentials?.length || 0,
                timestamp: new Date().toISOString()
            });

            // 调用浏览器API进行认证
            const authResp = await startAuthentication({ 
                optionsJSON: options,
                useBrowserAutofill: hasAutofillSupport // 根据浏览器支持情况启用自动填充
            });
            
            if (authResp.id) {
                setCurrentCredentialId(authResp.id);
                setShowModal(true);
                addDebugInfo({
                    action: '认证响应',
                    credentialId: authResp.id,
                    type: authResp.type,
                    timestamp: new Date().toISOString()
                });
            }

            // 完成认证
            const verificationResponse = await passkeyApi.finishAuthentication(username, authResp);
            if (!verificationResponse.success) {
                throw new Error('认证验证失败：' + verificationResponse.error);
            }

            // 使用 SimpleUser 类型
            const userData: SimpleUser = {
                id: verificationResponse.data.user.id,
                username: verificationResponse.data.user.username
            };

            // 登录成功处理
            await loginWithToken(verificationResponse.data.token, userData);
            showToast('Passkey 认证成功', 'success');
            return true;
            
        } catch (error: any) {
            let errorMessage = '认证失败';
            
            if (error?.name === 'NotAllowedError') {
                errorMessage = '用户取消了操作';
            } else if (error?.name === 'SecurityError') {
                errorMessage = '认证器可能不受此源信任';
            } else if (error?.message) {
                errorMessage = error.message;
            }
            
            addDebugInfo({
                action: '认证失败',
                error: errorMessage,
                errorDetails: error instanceof Error ? error.stack : String(error),
                timestamp: new Date().toISOString()
            });
            
            showToast(errorMessage, 'error');
            return false;
        } finally {
            setIsLoading(false);
        }
    }, [isSupported, hasAutofillSupport, loginWithToken, showToast, addDebugInfo]);

    // 删除认证器
    const removeAuthenticator = useCallback(async (credentialId: string) => {
        if (!isSupported) {
            showToast('您的浏览器不支持 Passkey', 'error');
            return;
        }

        try {
            setIsLoading(true);
            await passkeyApi.removeCredential(credentialId);
            showToast('Passkey 凭证已删除', 'success');
            await loadCredentials();
            
            addDebugInfo({
                action: '删除凭证',
                credentialId,
                success: true,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            if (error instanceof Error && error.message === 'Unauthorized') {
                showToast('登录已过期，请重新登录', 'error');
            } else {
                showToast('删除 Passkey 凭证失败', 'error');
            }
            
            addDebugInfo({
                action: '删除凭证失败',
                credentialId,
                error: error instanceof Error ? error.message : String(error),
                timestamp: new Date().toISOString()
            });
        } finally {
            setIsLoading(false);
        }
    }, [isSupported, loadCredentials, showToast, addDebugInfo]);

    return {
        credentials,
        isLoading,
        isSupported,
        hasAutofillSupport,
        supportChecked,
        loadCredentials,
        registerAuthenticator,
        removeAuthenticator,
        authenticateWithPasskey,
        showModal,
        setShowModal,
        currentCredentialId,
        setCurrentCredentialId,
        showDebugModal,
        setShowDebugModal,
        debugInfos,
        addDebugInfo
    };
}; 