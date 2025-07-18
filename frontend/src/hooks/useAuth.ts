import { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { useNavigate, useLocation } from 'react-router-dom';
import { User } from '../types/auth';

// 获取API基础URL
const getApiBaseUrl = () => {
    if (import.meta.env.DEV) return '';
    if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
    return 'https://tts-api.hapxs.com';
};

// 创建axios实例
const api = axios.create({
    baseURL: getApiBaseUrl(),
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    timeout: 5000 // 5秒超时
});

api.interceptors.request.use(config => {
    const token = localStorage.getItem('token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
        // 添加调试日志
        console.log('设置Authorization头:', `Bearer ${token}`);
    }
    return config;
});

// 添加请求拦截器
api.interceptors.response.use(
    (response) => response,
    (error) => {
        // 移除自动重试逻辑，直接返回错误
        return Promise.reject(error);
    }
);

export const useAuth = () => {
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const [pendingTOTP, setPendingTOTP] = useState<{ userId: string; token: string } | null>(null);
    const [pending2FA, setPending2FA] = useState<{ userId: string; token: string; type: string[]; username?: string } | null>(null);
    const navigate = useNavigate();
    const location = useLocation();
    const [isChecking, setIsChecking] = useState(false);
    const [isAdminChecked, setIsAdminChecked] = useState(false);
    const [lastCheckTime, setLastCheckTime] = useState(0);
    const [lastErrorTime, setLastErrorTime] = useState(0);
    const CHECK_INTERVAL = 30000; // 30秒检查一次
    const ERROR_RETRY_INTERVAL = 60000; // 错误后60秒再重试
    
    // 使用ref来跟踪检查状态，避免闭包问题
    const checkingRef = useRef(false);
    const lastCheckRef = useRef(0);
    const lastErrorRef = useRef(0);
    const isAdminCheckedRef = useRef(false);
    const locationPathRef = useRef('');

    // 更新ref值
    isAdminCheckedRef.current = isAdminChecked;
    locationPathRef.current = location.pathname;

    const checkAuth = useCallback(async () => {
        // 使用ref来防止重复请求
        if (checkingRef.current) return;
        
        const now = Date.now();
        const timeSinceLastCheck = now - lastCheckRef.current;
        const timeSinceLastError = now - lastErrorRef.current;
        
        // 检查时间间隔
        if (timeSinceLastCheck < CHECK_INTERVAL || timeSinceLastError < ERROR_RETRY_INTERVAL) {
            return;
        }
        
        checkingRef.current = true;
        setIsChecking(true);
        
        try {
            const token = localStorage.getItem('token');
            if (!token) {
                setUser(null);
                setLoading(false);
                return;
            }
            
            console.log('检查认证状态，token:', token);
            
            const response = await api.get<User>('/api/auth/me', {
                headers: { Authorization: `Bearer ${token}` }
            });
            
            console.log('认证检查响应:', response.status, response.data);
            
            if (response.status === 401 || response.status === 403) {
                // 清除无效token
                localStorage.removeItem('token');
                setUser(null);
                setLoading(false);
                return;
            }
            
            const data = response.data;
            if (data) {
                setUser(data);
                if (data.role === 'admin' && !isAdminCheckedRef.current) {
                    setIsAdminChecked(true);
                    // 排除特定路径，避免管理员访问这些页面时被重定向
                    const excludedPaths = ['/policy', '/welcome', '/admin/users'];
                    if (locationPathRef.current !== '/' && !excludedPaths.includes(locationPathRef.current)) {
                        navigate('/', { replace: true });
                    }
                }
            } else {
                setUser(null);
                localStorage.removeItem('token');
            }
            
            // 更新最后检查时间
            lastCheckRef.current = now;
            setLastCheckTime(now);
            
        } catch (error: any) {
            // 记录错误时间
            lastErrorRef.current = now;
            setLastErrorTime(now);
            
            if (error.response?.status === 429) {
                // 429错误不清理用户状态，只是记录错误时间
                console.warn('认证检查被限流，将在60秒后重试');
            } else {
                // 其他错误才清理用户状态
                setUser(null);
                localStorage.removeItem('token');
            }
        } finally {
            setLoading(false);
            setIsChecking(false);
            checkingRef.current = false;
        }
    }, []); // 移除所有依赖项，使用ref来避免闭包问题

    // 使用useEffect来定期检查认证状态
    useEffect(() => {
        // 初始检查
        checkAuth();
        
        const interval = setInterval(() => {
            checkAuth();
        }, CHECK_INTERVAL);
        
        return () => clearInterval(interval);
    }, []); // 移除checkAuth依赖项，避免重复触发

    const login = async (username: string, password: string) => {
        try {
            const response = await api.post<{ user: User; token: string; requires2FA?: boolean; twoFactorType?: string[] }>('/api/auth/login', {
                identifier: username,
                password
            });
            const { user, token, requires2FA, twoFactorType } = response.data;
            if (requires2FA && twoFactorType && twoFactorType.length > 0) {
                // 记录二次验证信息（不输出到控制台）
                const twoFactorInfo = {
                    action: '登录需要二次验证',
                    userId: user.id,
                    username: user.username,
                    twoFactorType,
                    requires2FA,
                    timestamp: new Date().toISOString()
                };
                
                setPending2FA({ userId: user.id, token, type: twoFactorType, username: user.username });
                return { requires2FA: true, user, token, twoFactorType };
            } else {
                localStorage.setItem('token', token);
                setUser(user);
                lastCheckRef.current = Date.now();
                setLastCheckTime(Date.now());
                // 添加调试日志
                console.log('登录成功，保存token:', token);
                console.log('用户信息:', user);
                return { requires2FA: false };
            }
        } catch (error: any) {
            const msg = error.response?.data?.error || error.message || '登录失败，请检查网络或稍后重试';
            throw new Error(msg);
        }
    };

    // 新增：使用 token 和用户信息直接登录（用于 Passkey 认证）
    const loginWithToken = async (token: string, user: User) => {
        localStorage.setItem('token', token);
        setUser(user);
        lastCheckRef.current = Date.now();
        setLastCheckTime(Date.now());
    };

    const verifyTOTP = async (token: string, backupCode?: string) => {
        if (!pendingTOTP) {
            throw new Error('没有待验证的TOTP请求');
        }

        try {
            const response = await api.post('/api/totp/verify-token', {
                userId: pendingTOTP.userId,
                token: backupCode ? undefined : token,
                backupCode
            }, {
                headers: { Authorization: `Bearer ${pendingTOTP.token}` }
            });

            if (response.data.verified) {
                // TOTP验证成功，完成登录
                localStorage.setItem('token', pendingTOTP.token);
                const userData = await getUserById(pendingTOTP.userId);
                setUser(userData);
                setPendingTOTP(null);
                // 登录成功后立即更新检查时间，避免重复请求
                lastCheckRef.current = Date.now();
                setLastCheckTime(Date.now());
                return true;
            } else {
                throw new Error('TOTP验证失败');
            }
        } catch (error: any) {
            // TOTP验证失败时清理pendingTOTP状态
            setPendingTOTP(null);
            
            const errorData = error.response?.data;
            
            if (error.response?.status === 429) {
                // 验证尝试次数过多
                const remainingTime = Math.ceil((errorData.lockedUntil - Date.now()) / 1000 / 60);
                throw new Error(`验证尝试次数过多，请${remainingTime}分钟后再试`);
            } else if (errorData?.remainingAttempts !== undefined) {
                // 显示剩余尝试次数
                const remainingAttempts = errorData.remainingAttempts;
                if (remainingAttempts === 0) {
                    const remainingTime = Math.ceil((errorData.lockedUntil - Date.now()) / 1000 / 60);
                    throw new Error(`验证码错误，账户已被锁定，请${remainingTime}分钟后再试`);
                } else {
                    throw new Error(`验证码错误，还剩${remainingAttempts}次尝试机会`);
                }
            } else {
                const msg = errorData?.error || error.message || 'TOTP验证失败';
                throw new Error(msg);
            }
        }
    };

    const getUserById = useCallback(async (userId: string): Promise<User> => {
        try {
            // 使用正确的token而不是userId
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('没有有效的认证token');
            }
            
            const response = await api.get<User>(`/api/auth/me`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            return response.data;
        } catch (error: any) {
            // 记录获取用户信息失败（不输出到控制台）
            const getUserErrorInfo = {
                action: '获取用户信息失败',
                error: error instanceof Error ? error.message : String(error),
                timestamp: new Date().toISOString()
            };
            throw new Error('获取用户信息失败');
        }
    }, []);

    const register = async (username: string, email: string, password: string) => {
        try {
            const response = await api.post<{ user: User; token: string }>('/api/auth/register', {
                username,
                email,
                password
            });
            const { user, token } = response.data;
            localStorage.setItem('token', token);
            setUser(user);
            // 注册成功后立即更新检查时间，避免重复请求
            lastCheckRef.current = Date.now();
            setLastCheckTime(Date.now());
        } catch (error: any) {
            const msg = error.response?.data?.error || error.message || '注册失败，请检查网络或稍后重试';
            throw new Error(msg);
        }
    };

    const logout = async () => {
        // 只清除本地 token 和用户状态，不请求后端接口
        localStorage.removeItem('token');
        setUser(null);
        setPendingTOTP(null);
        setPending2FA(null);
        setIsAdminChecked(false);
        navigate('/welcome');
    };

    return {
        user,
        loading,
        pendingTOTP,
        pending2FA,
        setPending2FA,
        login,
        loginWithToken,
        verifyTOTP,
        register,
        logout,
        api
    };
}; 