import express from 'express';
import { PasskeyService } from '../services/passkeyService';
import { PasskeyDataRepairService } from '../services/passkeyDataRepairService';
import { PasskeyCredentialIdFixer } from '../utils/passkeyCredentialIdFixer';
import { authenticateToken } from '../middleware/authenticateToken';
import { UserStorage, User } from '../utils/userStorage';
import logger from '../utils/logger';
import { rateLimitMiddleware } from '../middleware/rateLimit';
import { normalizeCredentialId, isValidCredentialId, formatAuthenticationResponse } from '../utils/credentialUtils';

const router = express.Router();

// 获取用户的 Passkey 凭证列表
router.get('/credentials', authenticateToken, async (req, res) => {
    try {
        const userId = (req as any).user.id;
        const credentials = await PasskeyService.getCredentials(userId);
        res.json(credentials);
    } catch (error) {
        console.error('获取 Passkey 凭证列表失败:', error);
        res.status(500).json({ error: '获取 Passkey 凭证列表失败' });
    }
});

// 开始注册 Passkey
router.post('/register/start', authenticateToken, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = (req as any).user?.id;
        const { credentialName } = req.body;
        const ip = req.headers['x-real-ip'] || req.ip || 'unknown';
        logger.info('[Passkey] /register/start 收到请求', { userId, credentialName, ip, headers: req.headers });

        if (!credentialName || typeof credentialName !== 'string') {
            logger.warn('[Passkey] credentialName 缺失或类型错误', { userId, credentialName, body: req.body });
            return res.status(400).json({ error: '认证器名称是必需的', details: { credentialName, type: typeof credentialName, body: req.body } });
        }
        if (!userId || typeof userId !== 'string') {
            logger.error('[Passkey] userId 缺失或类型错误', { userId, headers: req.headers });
            return res.status(401).json({ error: '用户未登录或 userId 异常', details: { userId, headers: req.headers } });
        }

        const user = await UserStorage.getUserById(userId);
        logger.info('[Passkey] /register/start 获取用户', { userId, user });
        if (!user) {
            logger.warn('[Passkey] 用户不存在', { userId });
            return res.status(404).json({ error: '用户不存在', details: { userId } });
        }
        if (!user.id || typeof user.id !== 'string') {
            logger.error('[Passkey] user.id 缺失或类型错误', { user });
            return res.status(500).json({ error: '用户ID异常', details: { user } });
        }
        if (!user.username || typeof user.username !== 'string') {
            logger.error('[Passkey] user.username 缺失或类型错误', { user });
            return res.status(500).json({ error: '用户名异常', details: { user } });
        }

        let options;
        try {
            options = await PasskeyService.generateRegistrationOptions(user, credentialName);
        } catch (err) {
            logger.error('[Passkey] generateRegistrationOptions error', { userId, credentialName, err });
            return res.status(500).json({ error: '生成注册选项失败', details: err instanceof Error ? err.message : String(err) });
        }

        if (!options) {
            logger.error('[Passkey] options 为 undefined', { userId, credentialName });
            return res.status(500).json({ error: '生成注册选项失败', details: { userId, credentialName, options } });
        }

        if (!options.challenge) {
            logger.error('[Passkey] options.challenge 为 undefined', { userId, credentialName, options });
            return res.status(500).json({ error: '生成注册选项失败: 缺少 challenge', details: { userId, credentialName, options } });
        }

        if (!options.user?.id) {
            logger.error('[Passkey] options.user.id 为 undefined', { userId, credentialName, options });
            return res.status(500).json({ error: '生成注册选项失败: 缺少用户ID', details: { userId, credentialName, options } });
        }

        logger.info('[Passkey] 生成的注册选项', {
            userId,
            challenge: options.challenge.substring(0, 20) + '...',
            rpId: options.rp?.id,
            userVerification: options.authenticatorSelection?.userVerification,
            attestationType: options.attestation,
            excludeCredentialsCount: options.excludeCredentials?.length || 0
        });

        await UserStorage.updateUser(userId, {
            pendingChallenge: options.challenge
        });

        res.json({ options });
    } catch (error) {
        logger.error('生成 Passkey 注册选项失败', { error: error instanceof Error ? error.stack : error, body: req.body, headers: req.headers });
        res.status(500).json({ error: '生成 Passkey 注册选项失败', details: error instanceof Error ? error.message : String(error) });
    }
});

// 完成注册 Passkey
router.post('/register/finish', authenticateToken, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = (req as any).user.id;
        const { credentialName, response } = req.body;
        if (!credentialName || !response) {
            return res.status(400).json({ error: '认证器名称和响应是必需的' });
        }
        const user = await UserStorage.getUserById(userId);
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }
        // 自动获取请求origin
        const requestOrigin = req.headers.origin || req.headers.referer || 'http://localhost:3001';
        const verification = await PasskeyService.verifyRegistration(user, response, credentialName, requestOrigin);
        res.json(verification);
    } catch (error) {
        console.error('完成 Passkey 注册失败:', error);
        res.status(500).json({ error: '完成 Passkey 注册失败' });
    }
});

// 开始认证
router.post('/authenticate/start', rateLimitMiddleware, async (req, res) => {
    try {
        const { username } = req.body;
        const ip = req.headers['x-real-ip'] || req.ip || 'unknown';
        
        logger.info('[Passkey] /authenticate/start 收到请求', { username, ip, headers: req.headers });

        if (!username) {
            logger.warn('[Passkey] 用户名缺失', { body: req.body });
            return res.status(400).json({ error: '用户名是必需的' });
        }

        const user = await UserStorage.getUserByUsername(username);
        if (!user) {
            logger.warn('[Passkey] 用户不存在', { username });
            return res.status(404).json({ error: '用户不存在' });
        }

        logger.info('[Passkey] 获取用户信息', { 
            userId: user.id, 
            username: user.username,
            passkeyEnabled: user.passkeyEnabled,
            credentialsCount: user.passkeyCredentials?.length || 0,
            searchUsername: username
        });

        if (!user.passkeyEnabled || !user.passkeyCredentials || user.passkeyCredentials.length === 0) {
            logger.warn('[Passkey] 用户未启用Passkey或无凭证', { 
                userId: user.id, 
                passkeyEnabled: user.passkeyEnabled,
                credentialsCount: user.passkeyCredentials?.length || 0
            });
            return res.status(400).json({ error: '用户未启用 Passkey 或没有注册的凭证' });
        }

        const options = await PasskeyService.generateAuthenticationOptions(user);
        
        logger.info('[Passkey] 生成认证选项成功', { 
            userId: user.id, 
            challenge: options.challenge?.substring(0, 20) + '...',
            allowCredentialsCount: options.allowCredentials?.length || 0,
            fullOptions: JSON.stringify(options, null, 2)
        });
        
        // 保存 challenge 到用户数据中
        await UserStorage.updateUser(user.id, {
            pendingChallenge: options.challenge
        });

        res.json({ options });
    } catch (error: any) {
        logger.error('[Passkey] 生成认证选项失败', { 
            error: error.message, 
            stack: error.stack,
            body: req.body,
            username: req.body.username
        });
        
        const errorMessage = error?.message || '生成 Passkey 认证选项失败';
        res.status(500).json({ error: errorMessage });
    }
});

// 完成认证
router.post('/authenticate/finish', rateLimitMiddleware, async (req, res) => {
    try {
        const { username, response } = req.body;
        if (!username || !response) {
            return res.status(400).json({ error: '用户名和响应是必需的' });
        }
        
        // 格式化响应对象
        const formattedResponse = formatAuthenticationResponse(response);
        
        // 调试日志：记录接收到的响应对象
        logger.info('[Passkey] /authenticate/finish 收到请求', {
            username,
            responseKeys: Object.keys(formattedResponse),
            hasId: !!formattedResponse.id,
            type: formattedResponse.type,
            idLength: formattedResponse.id?.length,
            idValue: formattedResponse.id?.substring(0, 20) + '...',
            fullResponse: JSON.stringify(formattedResponse, null, 2)
        });
        
        const user = await UserStorage.getUserByUsername(username);
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }
        // 自动获取请求origin
        const requestOrigin = req.headers.origin || req.headers.referer || 'http://localhost:3001';
        const verification = await PasskeyService.verifyAuthentication(user, formattedResponse, requestOrigin);
        const token = await PasskeyService.generateToken(user);
        res.json({
            success: true,
            token: token,
            user: { id: user.id, username: user.username }
        });
    } catch (error: any) {
        console.error('完成 Passkey 认证失败:', error);
        const errorMessage = error?.message || '完成 Passkey 认证失败';
        res.status(500).json({ error: errorMessage });
    }
});

// 删除 Passkey 凭证
router.delete('/credentials/:credentialId', authenticateToken, rateLimitMiddleware, async (req, res) => {
    try {
        const userId = (req as any).user.id;
        const { credentialId } = req.params;

        if (!credentialId) {
            return res.status(400).json({ error: '凭证ID是必需的' });
        }

        // 标准化 credentialId 格式
        const normalizedCredentialId = normalizeCredentialId(credentialId);
        if (!normalizedCredentialId || !isValidCredentialId(normalizedCredentialId)) {
            return res.status(400).json({ error: '无效的凭证ID格式' });
        }

        await PasskeyService.removeCredential(userId, normalizedCredentialId);
        res.json({ success: true });
    } catch (error) {
        console.error('删除 Passkey 凭证失败:', error);
        res.status(500).json({ error: '删除 Passkey 凭证失败' });
    }
});

// 检查当前用户的Passkey数据状态（需要认证）
router.get('/data/check', authenticateToken, async (req, res) => {
    try {
        const userId = (req as any).user.id;
        const result = await PasskeyDataRepairService.checkUserPasskeyData(userId);
        
        res.json({
            success: true,
            data: result
        });
    } catch (error) {
        logger.error('[Passkey] 检查用户数据状态失败', { 
            userId: (req as any).user.id,
            error: error instanceof Error ? error.message : String(error) 
        });
        res.status(500).json({ error: '检查数据状态失败' });
    }
});

// 修复当前用户的Passkey数据（需要认证）
router.post('/data/repair', authenticateToken, async (req, res) => {
    try {
        const userId = (req as any).user.id;
        const result = await PasskeyDataRepairService.repairUserPasskeyData(userId);
        
        if (result.success) {
            res.json({
                success: true,
                message: result.message,
                repairedCredentialsCount: result.repairedCredentialsCount
            });
        } else {
            res.status(400).json({
                success: false,
                error: result.message
            });
        }
    } catch (error) {
        logger.error('[Passkey] 修复用户数据失败', { 
            userId: (req as any).user.id,
            error: error instanceof Error ? error.message : String(error) 
        });
        res.status(500).json({ error: '修复数据失败' });
    }
});

// 管理员接口：检查所有用户的Passkey数据状态（需要管理员权限）
router.get('/admin/data/check-all', authenticateToken, async (req, res) => {
    try {
        const user = (req as any).user;
        
        // 检查管理员权限
        if (user.role !== 'admin') {
            return res.status(403).json({ error: '需要管理员权限' });
        }
        
        const allUsers = await UserStorage.getAllUsers();
        const results = [];
        
        for (const user of allUsers) {
            if (user.passkeyEnabled && user.passkeyCredentials && user.passkeyCredentials.length > 0) {
                const checkResult = await PasskeyDataRepairService.checkUserPasskeyData(user.id);
                results.push({
                    userId: user.id,
                    username: user.username,
                    ...checkResult
                });
            }
        }
        
        res.json({
            success: true,
            data: {
                totalUsers: allUsers.length,
                usersWithPasskey: results.length,
                results
            }
        });
    } catch (error) {
        logger.error('[Passkey] 管理员检查所有用户数据失败', { 
            error: error instanceof Error ? error.message : String(error) 
        });
        res.status(500).json({ error: '检查所有用户数据失败' });
    }
});

// 管理员接口：修复所有用户的Passkey数据（需要管理员权限）
router.post('/admin/data/repair-all', authenticateToken, async (req, res) => {
    try {
        const user = (req as any).user;
        
        // 检查管理员权限
        if (user.role !== 'admin') {
            return res.status(403).json({ error: '需要管理员权限' });
        }
        
        await PasskeyDataRepairService.repairAllUsersPasskeyData();
        
        res.json({
            success: true,
            message: '所有用户Passkey数据修复完成'
        });
    } catch (error) {
        logger.error('[Passkey] 管理员修复所有用户数据失败', { 
            error: error instanceof Error ? error.message : String(error) 
        });
        res.status(500).json({ error: '修复所有用户数据失败' });
    }
});

// 修复当前用户的credentialID（需要认证）
router.post('/credential-id/fix', authenticateToken, async (req, res) => {
    try {
        const userId = (req as any).user.id;
        const result = await PasskeyCredentialIdFixer.fixUserCredentialIds(userId);
        
        if (result.success) {
            res.json({
                success: true,
                message: result.message,
                fixedCredentials: result.fixedCredentials,
                totalCredentials: result.totalCredentials
            });
        } else {
            res.status(400).json({
                success: false,
                error: result.message
            });
        }
    } catch (error) {
        logger.error('[Passkey] 修复用户credentialID失败', { 
            userId: (req as any).user.id,
            error: error instanceof Error ? error.message : String(error) 
        });
        res.status(500).json({ error: '修复credentialID失败' });
    }
});

// 检查当前用户的credentialID状态（需要认证）
router.get('/credential-id/check', authenticateToken, async (req, res) => {
    try {
        const userId = (req as any).user.id;
        const user = await UserStorage.getUserById(userId);
        
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }
        
        if (!user.passkeyEnabled || !user.passkeyCredentials || user.passkeyCredentials.length === 0) {
            return res.json({
                success: true,
                hasPasskey: false,
                message: '用户未启用Passkey或无凭证'
            });
        }
        
        const credentialInfo = user.passkeyCredentials.map((cred, index) => ({
            index,
            credentialId: cred.credentialID,
            name: cred.name,
            isPasskey: (cred as any).isPasskey || false,
            credentialDeviceType: (cred as any).credentialDeviceType,
            credentialBackedUp: (cred as any).credentialBackedUp,
            ...PasskeyCredentialIdFixer.getCredentialIdInfo(cred.credentialID)
        }));
        
        const validCredentials = credentialInfo.filter(info => info.isValid);
        const invalidCredentials = credentialInfo.filter(info => !info.isValid);
        const passkeyCredentials = credentialInfo.filter(info => info.isPasskey);
        
        res.json({
            success: true,
            hasPasskey: true,
            totalCredentials: user.passkeyCredentials.length,
            validCredentials: validCredentials.length,
            invalidCredentials: invalidCredentials.length,
            passkeyCredentials: passkeyCredentials.length,
            needsFix: invalidCredentials.length > 0,
            credentialDetails: credentialInfo
        });
    } catch (error) {
        logger.error('[Passkey] 检查用户credentialID状态失败', { 
            userId: (req as any).user.id,
            error: error instanceof Error ? error.message : String(error) 
        });
        res.status(500).json({ error: '检查credentialID状态失败' });
    }
});

// 获取当前用户的Passkey统计信息（需要认证）
router.get('/stats', authenticateToken, async (req, res) => {
    try {
        const userId = (req as any).user.id;
        const user = await UserStorage.getUserById(userId);
        
        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }
        
        if (!user.passkeyEnabled || !user.passkeyCredentials || user.passkeyCredentials.length === 0) {
            return res.json({
                success: true,
                hasPasskey: false,
                stats: {
                    totalCredentials: 0,
                    passkeyCredentials: 0,
                    hardwareCredentials: 0,
                    validCredentials: 0,
                    invalidCredentials: 0
                }
            });
        }
        
        const stats = {
            totalCredentials: user.passkeyCredentials.length,
            passkeyCredentials: user.passkeyCredentials.filter(cred => (cred as any).isPasskey).length,
            hardwareCredentials: user.passkeyCredentials.filter(cred => !(cred as any).isPasskey).length,
            validCredentials: user.passkeyCredentials.filter(cred => 
                isValidCredentialId(cred.credentialID)
            ).length,
            invalidCredentials: user.passkeyCredentials.filter(cred => 
                !isValidCredentialId(cred.credentialID)
            ).length
        };
        
        res.json({
            success: true,
            hasPasskey: true,
            stats
        });
    } catch (error) {
        logger.error('[Passkey] 获取用户Passkey统计信息失败', { 
            userId: (req as any).user.id,
            error: error instanceof Error ? error.message : String(error) 
        });
        res.status(500).json({ error: '获取Passkey统计信息失败' });
    }
});

// 管理员接口：修复所有用户的credentialID（需要管理员权限）
router.post('/admin/credential-id/fix-all', authenticateToken, async (req, res) => {
    try {
        const user = (req as any).user;
        
        // 检查管理员权限
        if (user.role !== 'admin') {
            return res.status(403).json({ error: '需要管理员权限' });
        }
        
        const result = await PasskeyCredentialIdFixer.fixAllUsersCredentialIds();
        
        if (result.success) {
            res.json({
                success: true,
                message: result.message,
                totalUsers: result.totalUsers,
                fixedUsers: result.fixedUsers,
                totalFixedCredentials: result.totalFixedCredentials
            });
        } else {
            res.status(400).json({
                success: false,
                error: result.message
            });
        }
    } catch (error) {
        logger.error('[Passkey] 管理员修复所有用户credentialID失败', { 
            error: error instanceof Error ? error.message : String(error) 
        });
        res.status(500).json({ error: '修复所有用户credentialID失败' });
    }
});

export default router; 