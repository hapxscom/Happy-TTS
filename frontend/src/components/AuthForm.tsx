import React, { useState, useEffect, startTransition, Suspense } from 'react';
import { useAuth } from '../hooks/useAuth';
import { Link } from 'react-router-dom';
import DOMPurify from 'dompurify';
import AlertModal from './AlertModal';
import TOTPVerification from './TOTPVerification';
import { usePasskey } from '../hooks/usePasskey';
import { DebugInfoModal } from './DebugInfoModal';
import VerificationMethodSelector from './VerificationMethodSelector';
import PasskeyVerifyModal from './PasskeyVerifyModal';
import api from '../api/index';
import { useNotification } from './Notification';
import VerifyCodeInput from './VerifyCodeInput';
import { AnimatePresence, motion } from 'framer-motion';
import { NotificationData } from './Notification';
import getApiBaseUrl from '../api';
interface AuthFormProps {
  setNotification?: (data: NotificationData) => void;
}

interface PasswordStrength {
    score: number;
    feedback: string;
}

// ErrorBoundary 组件
class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean }> {
    constructor(props: { children: React.ReactNode }) {
        super(props);
        this.state = { hasError: false };
    }
    static getDerivedStateFromError(error: any) {
        return { hasError: true };
    }
    render() {
        if (this.state.hasError) {
            return <div>加载失败，请重试。</div>;
        }
        return this.props.children;
    }
}

export const AuthForm: React.FC<AuthFormProps> = ({ setNotification: propSetNotification }) => {
    const { setNotification: contextSetNotification } = useNotification();
    const setNotify = propSetNotification || contextSetNotification;
    const { login, register, pending2FA, setPending2FA, verifyTOTP } = useAuth();
    const { 
        authenticateWithPasskey, 
        showDebugModal, 
        setShowDebugModal, 
        debugInfos 
    } = usePasskey();
    const [isLogin, setIsLogin] = useState(true);
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [agreed, setAgreed] = useState(false);
    const [passwordStrength, setPasswordStrength] = useState<PasswordStrength>({ score: 0, feedback: '' });
    const [showTOTPVerification, setShowTOTPVerification] = useState(false);
    const [pendingUser, setPendingUser] = useState<any>(null);
    const [pendingUserId, setPendingUserId] = useState<string>('');
    const [pendingToken, setPendingToken] = useState<string>('');
    const [showPasskeyVerification, setShowPasskeyVerification] = useState(false);
    const [showVerificationSelector, setShowVerificationSelector] = useState(false);
    const [pendingVerificationData, setPendingVerificationData] = useState<any>(null);
    const [showEmailVerify, setShowEmailVerify] = useState(false);
    const [pendingEmail, setPendingEmail] = useState('');
    const [verifyCode, setVerifyCode] = useState('');
    const [verifyError, setVerifyError] = useState('');
    const [verifyLoading, setVerifyLoading] = useState(false);
    const [verifyResendTimer, setVerifyResendTimer] = useState(0);

    // 支持的主流邮箱后缀
    const allowedDomains = [
      'gmail.com', 'outlook.com', 'qq.com', '163.com', '126.com',
      'hotmail.com', 'yahoo.com', 'icloud.com', 'foxmail.com'
    ];
    const emailPattern = new RegExp(
      `^[\\w.-]+@(${allowedDomains.map(d => d.replace('.', '\\.')).join('|')})$`
    );

    // 保留用户名列表
    const reservedUsernames = ['admin', 'root', 'system', 'test', 'administrator'];

    // 密码复杂度检查
    const checkPasswordStrength = (pwd: string): PasswordStrength => {
        let score = 0;
        let feedback = [];

        // 长度检查
        if (pwd.length < 8) {
            feedback.push('密码长度至少需要8个字符');
        } else if (pwd.length >= 12) {
            score += 2;
        } else {
            score += 1;
        }

        // 包含数字
        if (/\d/.test(pwd)) {
            score += 1;
        } else {
            feedback.push('需要包含数字');
        }

        // 包含小写字母
        if (/[a-z]/.test(pwd)) {
            score += 1;
        } else {
            feedback.push('需要包含小写字母');
        }

        // 包含大写字母
        if (/[A-Z]/.test(pwd)) {
            score += 1;
        } else {
            feedback.push('需要包含大写字母');
        }

        // 包含特殊字符
        if (/[!@#$%^&*(),.?":{}|<>]/.test(pwd)) {
            score += 1;
        } else {
            feedback.push('需要包含特殊字符');
        }

        // 防止常见密码模式
        const commonPatterns = [
            /^123/, /password/i, /qwerty/i, /abc/i,
            new RegExp(username, 'i')
        ];
        if (commonPatterns.some(pattern => pattern.test(pwd))) {
            score = 0;
            feedback.push('请避免使用常见密码模式');
        }

        return {
            score,
            feedback: feedback.join('、')
        };
    };

    // 输入验证
    const validateInput = (value: string, type: 'username' | 'email' | 'password'): string | null => {
        // 清理输入
        const sanitizedValue = DOMPurify.sanitize(value).trim();

        switch (type) {
            case 'username':
                // 用户名：3-20个字符，只允许字母、数字、下划线
                if (!/^[a-zA-Z0-9_]{3,20}$/.test(sanitizedValue)) {
                    return '用户名只能包含字母、数字和下划线，长度3-20个字符';
                }
                // 仅注册时校验保留用户名
                if (!isLogin && reservedUsernames.includes(sanitizedValue.toLowerCase())) {
                    return '该用户名为保留字段，不能注册';
                }
                // 防止SQL注入相关字符
                if (/[\'\;"]/.test(sanitizedValue)) {
                    return '用户名包含非法字符';
                }
                break;
            case 'email':
                // 邮箱格式验证（只允许主流邮箱）
                if (!emailPattern.test(sanitizedValue)) {
                    return '只支持主流邮箱（如gmail、outlook、qq、163、126、hotmail、yahoo、icloud、foxmail等）';
                }
                break;
            case 'password':
                const strength = checkPasswordStrength(sanitizedValue);
                if (strength.score < 2) {
                    return strength.feedback || '密码强度不足';
                }
                break;
        }
        return null;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        // 输入验证
        const usernameError = validateInput(username, 'username');
        if (usernameError) {
            setError(usernameError);
            return;
        }

        if (!isLogin) {
            const emailError = validateInput(email, 'email');
            if (emailError) {
                setError(emailError);
                return;
            }

            // 只在注册时验证密码强度
            const passwordError = validateInput(password, 'password');
            if (passwordError) {
                setError(passwordError);
                return;
            }
        }

        if (!isLogin && password !== confirmPassword) {
            setError('两次输入的密码不一致');
            return;
        }

        if (!agreed) {
            setNotify({ message: '请勾选服务条款与隐私政策', type: 'warning' });
            return;
        }

        setLoading(true);

        try {
            // 对输入进行清理
            const sanitizedUsername = DOMPurify.sanitize(username).trim();
            const sanitizedEmail = DOMPurify.sanitize(email).trim();
            const sanitizedPassword = password;
            if (isLogin) {
                const result = await login(sanitizedUsername, sanitizedPassword);
                if (result && result.requires2FA && result.twoFactorType) {
                    setNotify({ message: '需要二次验证，请选择验证方式', type: 'info' });
                    setPendingUser(result.user);
                    setPendingUserId(result.user.id);
                    setPendingToken(result.token);
                    
                    // 检查是否同时启用了多种验证方式
                    const verificationTypes = result.twoFactorType;
                    const hasPasskey = verificationTypes.includes('Passkey');
                    const hasTOTP = verificationTypes.includes('TOTP');
                    
                    if (hasPasskey && hasTOTP) {
                        // 同时启用两种验证方式，显示选择弹窗
                        // 注意：不设置 pending2FA，避免自动弹出验证弹窗
                        setPendingVerificationData({
                            user: result.user,
                            userId: result.user.id,
                            token: result.token,
                            username: sanitizedUsername
                        });
                        startTransition(() => setShowVerificationSelector(true));
                    } else if (hasPasskey) {
                        // 只启用Passkey，直接显示Passkey验证弹窗
                        setPending2FA({ userId: result.user.id, username: sanitizedUsername, type: ['Passkey'] });
                        startTransition(() => setShowPasskeyVerification(true));
                    } else if (hasTOTP) {
                        // 只启用TOTP，直接显示TOTP验证弹窗
                        setPending2FA({ userId: result.user.id, username: sanitizedUsername, type: ['TOTP'] });
                        startTransition(() => setShowTOTPVerification(true));
                    }
                    return;
                }
                // 登录成功且不需要2FA，强制刷新页面
                if (typeof window !== 'undefined') {
                    setNotify({ message: '登录成功', type: 'success' });
                    window.location.reload();
                }
                return;
            } else {
                // 注册后进入邮箱验证码界面
                const res = await fetch(getApiBaseUrl() + '/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: sanitizedUsername,
                        email: sanitizedEmail,
                        password: sanitizedPassword
                    })
                });
                const data = await res.json();
                if (data && data.needVerify) {
                    setShowEmailVerify(true);
                    setPendingEmail(sanitizedEmail);
                    setNotify({ message: '验证码已发送到邮箱，请查收', type: 'info' });
                } else {
                    setError(data?.error || '注册失败，未收到验证码发送指示');
                    setNotify({ message: data?.error || '注册失败，未收到验证码发送指示', type: 'error' });
                }
            }
            // 登录成功后强制刷新页面，不需要回调函数
        } catch (err: any) {
            // 记录认证操作失败（不输出到控制台）
            const authOperationErrorInfo = {
                action: '认证操作失败',
                type: isLogin ? '登录' : '注册',
                error: err.message,
                timestamp: new Date().toISOString()
            };
            setError(err.message || '操作失败');
            setNotify({ message: err.message || '操作失败', type: 'error' });
        } finally {
            setLoading(false);
        }
    };

    // 切换登录/注册模式
    const handleModeSwitch = () => {
        startTransition(() => {
            setIsLogin(!isLogin);
            setError(null);
            setPassword('');
            setConfirmPassword('');
        });
    };

    // 实时密码强度检查
    useEffect(() => {
        if (!isLogin && (!username || !email)) {
            setPasswordStrength({ score: 0, feedback: '' });
            return;
        }
        if (password) {
            const strength = checkPasswordStrength(password);
            setPasswordStrength(strength);
        } else {
            setPasswordStrength({ score: 0, feedback: '' });
        }
    }, [password, username, email, isLogin]);

    // 修改useEffect逻辑，避免在显示验证方式选择器时自动弹出验证弹窗
    useEffect(() => {
        // 只有在不显示验证方式选择器时才自动弹出验证弹窗
        if (!showVerificationSelector && pending2FA && Array.isArray(pending2FA.type) && pending2FA.type.length === 1) {
            if (pending2FA.type[0] === 'Passkey' && !showPasskeyVerification) {
                startTransition(() => setShowPasskeyVerification(true));
            } else if (pending2FA.type[0] === 'TOTP' && !showTOTPVerification) {
                startTransition(() => setShowTOTPVerification(true));
            }
        }
    }, [pending2FA, showPasskeyVerification, showTOTPVerification, showVerificationSelector]);

    // Passkey验证弹窗逻辑
    const handlePasskeyVerify = async () => {
        setLoading(true);
        try {
            // 从 pending2FA 中获取用户名，如果没有则使用当前输入的用户名
            const currentUsername = pending2FA?.username || username;
            if (!currentUsername) {
                setError('无法获取用户名信息');
                return;
            }
            
            // 记录Passkey验证的用户名来源（不输出到控制台）
            const usernameSourceInfo = {
                action: 'Passkey验证用户名来源',
                pending2FAUsername: pending2FA?.username,
                currentInputUsername: username,
                finalUsername: currentUsername,
                timestamp: new Date().toISOString()
            };
            
            const success = await authenticateWithPasskey(currentUsername);
            if (success) {
                setNotify({ message: 'Passkey 验证成功', type: 'success' });
                startTransition(() => {
                    setShowPasskeyVerification(false);
                    setPending2FA(null);
                    // 认证成功后刷新页面
                    if (typeof window !== 'undefined') {
                        window.location.reload();
                    }
                });
            } else {
                setError('Passkey 验证失败');
                setNotify({ message: 'Passkey 验证失败', type: 'error' });
            }
        } catch (e: any) {
            setError(e.message || 'Passkey 验证失败');
        } finally {
            setLoading(false);
        }
    };

    // 验证方式选择处理
    const handleVerificationMethodSelect = async (method: 'passkey' | 'totp') => {
        startTransition(() => setShowVerificationSelector(false));
        setLoading(true);
        
        try {
            if (method === 'passkey') {
                // 处理Passkey验证 - 直接调用验证，不设置pending2FA
                const success = await authenticateWithPasskey(pendingVerificationData.username);
                if (success) {
                    startTransition(() => {
                        setPendingVerificationData(null);
                        // 认证成功后刷新页面
                        if (typeof window !== 'undefined') {
                            window.location.reload();
                        }
                    });
                } else {
                    setError('Passkey 验证失败');
                    setNotify({ message: 'Passkey 验证失败', type: 'error' });
                }
            } else if (method === 'totp') {
                // 选择TOTP验证方式，设置pending2FA并显示TOTP验证弹窗
                startTransition(() => {
                    setPending2FA({ userId: pendingVerificationData.userId, username: pendingVerificationData.username, type: ['TOTP'] });
                    setShowTOTPVerification(true);
                    setNotify({ message: '请进行 TOTP 验证', type: 'info' });
                });
            }
        } catch (e: any) {
            setError(e.message || '验证失败');
        } finally {
            setLoading(false);
        }
    };

    // 验证方式选择器关闭处理
    const handleVerificationSelectorClose = () => {
        startTransition(() => {
            setShowVerificationSelector(false);
            setPendingVerificationData(null);
            setPending2FA(null); // 清除pending2FA状态，防止其他弹窗自动显示
        });
    };

    // 邮箱验证码倒计时
    useEffect(() => {
        if (!showEmailVerify) return;
        if (verifyResendTimer <= 0) return;
        const timer = setInterval(() => {
            setVerifyResendTimer(t => t > 0 ? t - 1 : 0);
        }, 1000);
        return () => clearInterval(timer);
    }, [verifyResendTimer, showEmailVerify]);

    // 发送验证码（重发）
    const handleResendVerifyCode = async () => {
        if (verifyResendTimer > 0) return;
        setVerifyLoading(true);
        setVerifyError('');
        try {
            const res = await fetch(getApiBaseUrl() + '/api/auth/send-verify-email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: pendingEmail })
            });
            const data = await res.json();
            if (data && data.success) {
                setNotify({ message: '验证码已重新发送', type: 'success' });
                setVerifyResendTimer(60);
            } else {
                setVerifyError(data.error || '验证码发送失败');
                setNotify({ message: data.error || '验证码发送失败', type: 'error' });
            }
        } catch (err: any) {
            setVerifyError(err.message || '验证码发送失败');
            setNotify({ message: err.message || '验证码发送失败', type: 'error' });
        } finally {
            setVerifyLoading(false);
        }
    };

    const handleVerifyCode = async (code?: string) => {
        setVerifyLoading(true);
        setVerifyError('');
        const finalCode = code || verifyCode;
        if (!/^[0-9]{8}$/.test(finalCode)) {
            setVerifyError('验证码必须为8位数字');
            setVerifyLoading(false);
            return;
        }
        try {
            const res = await fetch(getApiBaseUrl() + '/api/auth/verify-email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: pendingEmail, code: finalCode })
            });
            const data = await res.json();
            if (data && data.success) {
                setShowEmailVerify(false);
                setPendingEmail('');
                setVerifyCode('');
                setVerifyError('');
                setIsLogin(true);
                setError('邮箱验证成功，请登录');
                setNotify({ message: '邮箱验证成功，请登录', type: 'success' });
            } else {
                setVerifyError(data.error || '验证码错误');
                setNotify({ message: data.error || '验证码错误', type: 'error' });
            }
        } catch (err: any) {
            setVerifyError(err.message || '验证码校验失败');
            setNotify({ message: err.message || '验证码校验失败', type: 'error' });
        } finally {
            setVerifyLoading(false);
        }
    };

    return (
        <div className="w-full min-h-screen flex items-center justify-center py-8 px-2">
            <div className="max-w-md w-full space-y-6 p-8 bg-white rounded-3xl shadow-2xl border border-blue-100 mx-auto animate-fade-in">
                <div>
                    <h2 className="text-center text-4xl font-extrabold text-indigo-700 mb-2 drop-shadow-lg tracking-wide">
                        {isLogin ? '登录' : '注册'}
                    </h2>
                    <div className="text-center text-gray-500 text-base mb-4">
                        欢迎使用 HappyTTS
                    </div>
                </div>
                <form className="space-y-6" onSubmit={handleSubmit}>
                    <div className="rounded-2xl shadow-sm -space-y-px bg-gradient-to-br from-blue-50 to-indigo-50 p-4">
                        <div>
                            <label htmlFor="username" className="sr-only">用户名</label>
                            <input
                                id="username"
                                name="username"
                                type="text"
                                required
                                className="appearance-none rounded-xl relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 focus:z-10 sm:text-base bg-white mb-3 transition-all duration-200"
                                placeholder="用户名 (3-20个字符，只允许字母、数字、下划线)"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                maxLength={20}
                                pattern="^[a-zA-Z0-9_]{3,20}$"
                            />
                        </div>
                        {!isLogin && (
                            <div>
                                <label htmlFor="email" className="sr-only">邮箱</label>
                                <input
                                    id="email"
                                    name="email"
                                    type="email"
                                    required
                                    className="appearance-none rounded-xl relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 focus:z-10 sm:text-base bg-white mb-3 transition-all duration-200"
                                    placeholder="邮箱"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                />
                            </div>
                        )}
                        <div>
                            <label htmlFor="password" className="sr-only">密码</label>
                            <input
                                id="password"
                                name="password"
                                type="password"
                                required
                                className="appearance-none rounded-xl relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 focus:z-10 sm:text-base bg-white mb-3 transition-all duration-200"
                                placeholder={isLogin ? "请输入密码" : "密码 (至少8位，包含大小写字母、数字和特殊字符)"}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                minLength={isLogin ? undefined : 8}
                            />
                            {!isLogin && password && (
                                <div className="relative">
                                    <div className="mt-1 p-2 text-sm text-gray-600 bg-gray-50 rounded border border-gray-200 break-words">
                                        <div className="mb-1">密码强度：
                                            <span className={`font-medium ${
                                                passwordStrength.score >= 4 ? 'text-green-600' :
                                                passwordStrength.score >= 3 ? 'text-blue-600' :
                                                passwordStrength.score >= 2 ? 'text-yellow-600' :
                                                'text-red-600'
                                            }`}>
                                                {(!username || !email) ? '请先填写用户名和邮箱' :
                                                passwordStrength.score >= 4 ? '很强' :
                                                passwordStrength.score >= 3 ? '强' :
                                                passwordStrength.score >= 2 ? '中等' :
                                                '弱'}
                                            </span>
                                        </div>
                                        {passwordStrength.feedback && !!username && !!email && (
                                            <div className="text-xs text-gray-500">
                                                {passwordStrength.feedback}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                        {!isLogin && (
                            <div>
                                <label htmlFor="confirmPassword" className="sr-only">确认密码</label>
                                <input
                                    id="confirmPassword"
                                    name="confirmPassword"
                                    type="password"
                                    required
                                    className="appearance-none rounded-xl relative block w-full px-4 py-3 border border-gray-300 placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-indigo-400 focus:z-10 sm:text-base bg-white mb-3 transition-all duration-200"
                                    placeholder="确认密码"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                />
                            </div>
                        )}
                    </div>

                    <div className="flex items-center">
                        <input
                            id="agree"
                            name="agree"
                            type="checkbox"
                            checked={agreed}
                            onChange={e => setAgreed(e.target.checked)}
                            className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                            required
                        />
                        <label htmlFor="agree" className="ml-2 block text-sm text-gray-700">
                            我已阅读并同意
                            <Link to="/policy" className="text-blue-600 hover:underline ml-1" target="_blank">
                                服务条款与隐私政策
                            </Link>
                        </label>
                    </div>

                    {error && (
                        <div className="text-red-500 text-base text-center font-bold bg-red-50 border border-red-200 rounded-lg py-2 px-3 mb-2 animate-pulse">
                            {error}
                        </div>
                    )}

                    <div>
                        <button
                            type="submit"
                            disabled={loading || (!isLogin && password !== confirmPassword)}
                            className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-lg font-bold rounded-2xl text-white bg-gradient-to-r from-indigo-500 to-blue-500 hover:from-indigo-600 hover:to-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-400 disabled:opacity-50 shadow-lg transition-all duration-200"
                        >
                            {loading ? '处理中...' : isLogin ? '登录' : '注册'}
                        </button>
                    </div>

                    <div className="text-sm text-center mt-2">
                        <button
                            type="button"
                            onClick={handleModeSwitch}
                            className="font-medium text-indigo-600 hover:text-indigo-500"
                        >
                            {isLogin ? '没有账号？点击注册' : '已有账号？点击登录'}
                        </button>
                    </div>
                </form>
            </div>
            {/* 服务条款与隐私政策弹窗已用 setNotification 全局弹窗替换 */}
            
            {/* Passkey 二次校验弹窗 */}
            <PasskeyVerifyModal
                open={showPasskeyVerification}
                username={username}
                onSuccess={() => { 
                    startTransition(() => { 
                        setShowPasskeyVerification(false); 
                        setPending2FA(null); 
                        setPendingVerificationData(null);
                        // 认证成功后刷新页面
                        if (typeof window !== 'undefined') {
                            window.location.reload(); 
                        }
                    }); 
                }}
                onClose={() => startTransition(() => {
                    setShowPasskeyVerification(false);
                    setPending2FA(null);
                    setPendingVerificationData(null);
                })}
            />
            {/* TOTP 验证弹窗 */}
            {showTOTPVerification && (
                <ErrorBoundary>
                    <TOTPVerification
                        isOpen={showTOTPVerification}
                        onClose={() => startTransition(() => {
                            setShowTOTPVerification(false);
                            setPending2FA(null);
                            setPendingVerificationData(null);
                        })}
                        onSuccess={() => {
                            startTransition(() => {
                                setShowTOTPVerification(false);
                                setPending2FA(null);
                                setPendingVerificationData(null);
                                // 认证成功后刷新页面
                                if (typeof window !== 'undefined') {
                                    window.location.reload();
                                }
                            });
                        }}
                        userId={pending2FA?.userId || ''}
                        token={pendingToken || ''}
                    />
                </ErrorBoundary>
            )}

            {/* 验证方式选择弹窗 */}
            {showVerificationSelector && pendingVerificationData && (
                <VerificationMethodSelector
                    isOpen={showVerificationSelector}
                    onClose={handleVerificationSelectorClose}
                    onSelectMethod={handleVerificationMethodSelect}
                    username={pendingVerificationData.username}
                    loading={loading}
                />
            )}

            {/* 调试信息弹窗 */}
            <DebugInfoModal
                isOpen={showDebugModal}
                onClose={() => startTransition(() => setShowDebugModal(false))}
                debugInfos={debugInfos}
            />

            {/* 调试信息按钮 */}
            {debugInfos.length > 0 && (
                <div className="fixed bottom-4 right-4 z-40">
                    <button
                        onClick={() => setShowDebugModal(true)}
                        className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg shadow-lg transition-colors flex items-center space-x-2"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <span>调试信息 ({debugInfos.length})</span>
                    </button>
                </div>
            )}

            {/* 邮箱验证码弹窗 */}
            <AnimatePresence>
            {showEmailVerify && (
                <motion.div
                    className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-30 z-50"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.25 }}
                >
                    <motion.div
                        className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-sm relative"
                        initial={{ scale: 0.95, opacity: 0, y: 40 }}
                        animate={{ scale: 1, opacity: 1, y: 0 }}
                        exit={{ scale: 0.95, opacity: 0, y: 40 }}
                        transition={{ duration: 0.28 }}
                    >
                        <h3 className="text-lg font-bold mb-4 text-center">邮箱验证</h3>
                        <p className="mb-2 text-gray-600 text-center">我们已向 <span className="font-semibold">{pendingEmail}</span> 发送了验证码，请输入收到的验证码完成注册。</p>
                        <VerifyCodeInput
                            length={8}
                            inputClassName="bg-blue-50 focus:bg-blue-100 border-blue-200 text-blue-900"
                            onComplete={async (code) => {
                                setVerifyCode(code);
                                // 自动触发验证
                                if (code.length === 8 && !verifyLoading) {
                                    await handleVerifyCode(code);
                                }
                            }}
                            loading={verifyLoading}
                            error={verifyError}
                        />
                        <button
                            className="w-full py-2 px-4 bg-indigo-600 text-white rounded-md font-semibold hover:bg-indigo-700 transition-all mb-2 mt-2"
                            onClick={() => handleVerifyCode()}
                            disabled={verifyLoading || verifyCode.length !== 8}
                        >
                            {verifyLoading ? '验证中...' : '提交验证'}
                        </button>
                        <button
                            className={`w-full py-2 px-4 rounded-md font-semibold mb-2 transition-all ${verifyResendTimer > 0 ? 'bg-gray-100 text-gray-400 cursor-not-allowed' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'}`}
                            onClick={handleResendVerifyCode}
                            disabled={verifyLoading || verifyResendTimer > 0}
                        >
                            {verifyResendTimer > 0 ? `重新发送（${verifyResendTimer}s）` : '重新发送验证码'}
                        </button>
                        <button
                            className="w-full py-2 px-4 bg-gray-200 text-gray-700 rounded-md font-semibold hover:bg-gray-300 transition-all"
                            onClick={() => setShowEmailVerify(false)}
                            disabled={verifyLoading}
                        >
                            取消
                        </button>
                    </motion.div>
                </motion.div>
            )}
            </AnimatePresence>
        </div>
    );
};