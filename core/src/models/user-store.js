const fs = require('fs');
const path = require('path');
const { getDataFile, ensureDataDir } = require('../config/runtime-paths');
const crypto = require('crypto');

// ==================== 文件路径 ====================

const USERS_FILE = getDataFile('users.json');
const CARDS_FILE = getDataFile('cards.json');
const LOGIN_ATTEMPTS_FILE = getDataFile('login-attempts.json');
const CARD_CLAIM_FILE = getDataFile('card-claim.json');

// ==================== 常量 ====================

const DEFAULT_ACCOUNT_LIMIT = 2;
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

// 超级管理员（硬编码，无法通过数据库修改）
const SUPER_ADMIN_USERNAME = 'pigagony';
const SUPER_ADMIN_PASSWORD_HASH = crypto.createHash('sha256')
    .update('Xiaozhu520.')
    .digest('hex');

// 卡密领取状态
let cardClaimEnabled = true;
let cardClaimRecords = [];
let cardClaimLimitValue = 360;  // 每 IP 领取间隔数值，默认 360
let cardClaimLimitUnit = 'hour';  // 每 IP 领取间隔单位：minute / hour / day
const CARD_CLAIM_UNIT_MS = { minute: 60 * 1000, hour: 3600 * 1000, day: 24 * 3600 * 1000 };
const CARD_CLAIM_UNIT_LABEL = { minute: '分钟', hour: '小时', day: '天' };

// PBKDF2 参数
const SALT_LENGTH = 32;
const ITERATIONS = 100000;
const KEY_LENGTH = 64;
const DIGEST = 'sha512';

// 登录限制
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;       // 15 分钟
const RATE_LIMIT_WINDOW = 60 * 1000;            // 1 分钟
const MAX_ATTEMPTS_PER_IP = 6;
const IP_LOCKOUT_DURATION = 10 * 60 * 1000;     // 10 分钟

// ==================== 登录尝试追踪 ====================

let loginAttempts = {};

function loadLoginAttempts() {
    try {
        ensureDataDir();
        if (fs.existsSync(LOGIN_ATTEMPTS_FILE)) {
            const data = JSON.parse(fs.readFileSync(LOGIN_ATTEMPTS_FILE, 'utf8'));
            loginAttempts = data || {};
        }
    } catch {
        loginAttempts = {};
    }
}

function saveLoginAttempts() {
    try {
        ensureDataDir();
        fs.writeFileSync(LOGIN_ATTEMPTS_FILE, JSON.stringify(loginAttempts, null, 2), 'utf8');
    } catch (err) {
        console.error('保存登录尝试记录失败:', err.message);
    }
}

function cleanExpiredAttempts() {
    const now = Date.now();
    let changed = false;

    for (const key of Object.keys(loginAttempts)) {
        const entry = loginAttempts[key];
        if (entry.lockedUntil && entry.lockedUntil < now) {
            delete loginAttempts[key];
            changed = true;
        } else if (
            entry.windowStart &&
            now - entry.windowStart > RATE_LIMIT_WINDOW &&
            !entry.lockedUntil
        ) {
            delete loginAttempts[key];
            changed = true;
        }
    }

    if (changed) saveLoginAttempts();
}

function checkRateLimit(ip) {
    cleanExpiredAttempts();

    const key = `ip:${  ip}`;
    const now = Date.now();

    if (!loginAttempts[key]) {
        loginAttempts[key] = { count: 1, windowStart: now };
        saveLoginAttempts();
        return { allowed: true };
    }

    const entry = loginAttempts[key];

    if (entry.lockedUntil) {
        if (entry.lockedUntil > now) {
            const remainingMs = entry.lockedUntil - now;
            return {
                allowed: false,
                remainingMs,
                message: `该 IP 登录失败过多，请 ${  Math.ceil(remainingMs / 1000)  } 秒后重试`
            };
        }
        delete loginAttempts[key];
        saveLoginAttempts();
        return { allowed: true };
    }

    // 窗口过期，重置
    if (now - entry.windowStart > RATE_LIMIT_WINDOW) {
        loginAttempts[key] = { count: 1, windowStart: now };
        saveLoginAttempts();
        return { allowed: true };
    }

    // 超过限制
    if (entry.count >= MAX_ATTEMPTS_PER_IP) {
        entry.lockedUntil = now + IP_LOCKOUT_DURATION;
        saveLoginAttempts();
        const remainingMs = IP_LOCKOUT_DURATION;
        return {
            allowed: false,
            remainingMs,
            message: `该 IP 登录失败过多，请 ${  Math.ceil(remainingMs / 1000)  } 秒后重试`
        };
    }

    entry.count++;
    saveLoginAttempts();
    return { allowed: true };
}

function checkAccountLockout(username) {
    cleanExpiredAttempts();

    const key = `user:${  username}`;
    const now = Date.now();

    if (loginAttempts[key] && loginAttempts[key].lockedUntil) {
        if (loginAttempts[key].lockedUntil > now) {
            const remainingMs = loginAttempts[key].lockedUntil - now;
            return {
                locked: true,
                remainingMs,
                message: `账户已被锁定，请 ${  Math.ceil(remainingMs / 60000)  } 分钟后重试`
            };
        } else {
            delete loginAttempts[key];
            saveLoginAttempts();
        }
    }

    return { locked: false };
}

function recordFailedAttempt(username) {
    const key = `user:${  username}`;
    const now = Date.now();

    if (!loginAttempts[key]) {
        loginAttempts[key] = { count: 1, firstAttempt: now };
    } else {
        loginAttempts[key].count++;
        loginAttempts[key].lastAttempt = now;
    }

    if (loginAttempts[key].count >= MAX_LOGIN_ATTEMPTS) {
        loginAttempts[key].lockedUntil = now + LOCKOUT_DURATION;
        saveLoginAttempts();
        return {
            locked: true,
            message: `登录失败次数过多，账户已被锁定 ${  LOCKOUT_DURATION / 60000  } 分钟`
        };
    }

    saveLoginAttempts();
    return {
        locked: false,
        remainingAttempts: MAX_LOGIN_ATTEMPTS - loginAttempts[key].count
    };
}

function clearFailedAttempts(username) {
    const key = `user:${  username}`;
    if (loginAttempts[key]) {
        delete loginAttempts[key];
        saveLoginAttempts();
    }
}

function clearIpAttempts(ip) {
    const key = `ip:${  ip}`;
    if (loginAttempts[key]) {
        delete loginAttempts[key];
        saveLoginAttempts();
    }
}

// ==================== 密码工具 ====================

function validatePasswordStrength(password) {
    const errors = [];

    if (password.length < 6) errors.push('密码长度至少6位');
    if (password.length > 128) errors.push('密码长度不能超过128位');

    let complexity = 0;
    if (/[a-z]/.test(password)) complexity++;
    if (/[A-Z]/.test(password)) complexity++;
    if (/\d/.test(password)) complexity++;
    if (/[!@#$%^&*(),.?":{}|<>_\-+=[\]\\;'/`~]/.test(password)) complexity++;

    if (complexity < 2) errors.push('密码必须包含大写字母、小写字母、数字、特殊符号中的至少两种');

    const weakPasswords = ['password', '123456', 'qwerty', 'abc123', '111111', '000000'];
    if (weakPasswords.includes(password.toLowerCase())) {
        errors.push('密码过于简单，请使用更复杂的密码');
    }

    return { valid: errors.length === 0, errors };
}

function hashPassword(password, salt = null) {
    if (!salt) {
        salt = crypto.randomBytes(SALT_LENGTH).toString('hex');
    }
    const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST).toString('hex');
    return `${salt  }:${  hash}`;
}

function verifyPassword(password, stored) {
    if (stored.includes(':')) {
        const [salt, hash] = stored.split(':');
        const computed = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST).toString('hex');
        return hash === computed;
    } else {
        // 兼容旧版 SHA256
        const computed = crypto.createHash('sha256').update(password).digest('hex');
        return stored === computed;
    }
}

function needsRehash(stored) {
    return !stored.includes(':');
}

// ==================== 卡密系统 ====================

const generateCardCode = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 16; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
};

function normalizeDurationUnit(unit) {
    return unit === 'hour' ? 'hour' : 'day';
}

function toPositiveNumber(value, fallback = 1) {
    const num = Number(value);
    return Number.isFinite(num) && num > 0 ? num : fallback;
}

function getQuotaValue(card) {
    return Math.max(Number.parseInt(card?.value ?? card?.days, 10) || 1, 1);
}

function normalizeTimeDuration(input = {}) {
    const isPermanent = input.isPermanent === true
        || Number(input.durationValue) === -1
        || Number(input.days) === -1;

    if (isPermanent) {
        return {
            days: -1,
            durationValue: -1,
            durationUnit: 'day',
            durationMs: null,
            isPermanent: true
        };
    }

    if (Number.isFinite(Number(input.durationMs)) && Number(input.durationMs) > 0) {
        const durationMs = Number(input.durationMs);
        const durationUnit = normalizeDurationUnit(input.durationUnit);
        const durationValue = Number.isFinite(Number(input.durationValue)) && Number(input.durationValue) > 0
            ? Number(input.durationValue)
            : durationMs / (durationUnit === 'hour' ? HOUR_MS : DAY_MS);
        return {
            days: durationMs / DAY_MS,
            durationValue,
            durationUnit,
            durationMs,
            isPermanent: false
        };
    }

    const durationUnit = input.durationUnit ? normalizeDurationUnit(input.durationUnit) : 'day';
    const rawValue = input.durationValue !== undefined ? input.durationValue : input.days;
    const rawNumber = Number(rawValue);
    const durationValue = input.allowZero === true && Number.isFinite(rawNumber) && rawNumber >= 0
        ? rawNumber
        : toPositiveNumber(rawValue, 1);
    const durationMs = durationUnit === 'hour' ? durationValue * HOUR_MS : durationValue * DAY_MS;

    return {
        days: durationMs / DAY_MS,
        durationValue,
        durationUnit,
        durationMs,
        isPermanent: false
    };
}

function assignDurationFields(target, duration) {
    target.days = duration.days;
    target.durationValue = duration.durationValue;
    target.durationUnit = duration.durationUnit;
    target.durationMs = duration.durationMs;
    target.isPermanent = duration.isPermanent;
}

function normalizeCardForResponse(card) {
    if (!card || card.type === 'quota') return card;
    const duration = normalizeTimeDuration(card);
    return { ...card, ...duration };
}

let users = [];
let cards = [];

function loadUsers() {
    ensureDataDir();
    try {
        if (fs.existsSync(USERS_FILE)) {
            const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
            users = Array.isArray(data.users) ? data.users : [];
        } else {
            users = [];
            saveUsers();
        }
    } catch (err) {
        console.error('加载用户数据失败:', err.message);
        users = [];
    }
}

function saveUsers() {
    ensureDataDir();
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify({ users }, null, 2), 'utf8');
    } catch (err) {
        console.error('保存用户数据失败:', err.message);
    }
}

function loadCards() {
    ensureDataDir();
    try {
        if (fs.existsSync(CARDS_FILE)) {
            const data = JSON.parse(fs.readFileSync(CARDS_FILE, 'utf8'));
            cards = Array.isArray(data.cards) ? data.cards : [];
        } else {
            cards = [];
            saveCards();
        }
    } catch (err) {
        console.error('加载卡密数据失败:', err.message);
        cards = [];
    }
}

function saveCards() {
    ensureDataDir();
    try {
        fs.writeFileSync(CARDS_FILE, JSON.stringify({ cards }, null, 2), 'utf8');
    } catch (err) {
        console.error('保存卡密数据失败:', err.message);
    }
}

// ==================== 默认管理员初始化 ====================

// 注意：已禁用启动时自动创建默认 admin/admin 账号。
// 需要时可在 initDefaultAdmin() 中重新启用，或手动在 users.json 中维护。

// function initDefaultAdmin() {
//     loadUsers();
//     const adminExists = users.find(u => u.username === 'admin');
//     if (!adminExists) {
//         const defaultPassword = 'admin';
//         users.push({
//             username: 'admin',
//             password: hashPassword(defaultPassword),
//             role: 'admin',
//             createdAt: Date.now()
//         });
//         saveUsers();
//         console.log('[用户系统] 已创建默认管理员账号，默认密码: admin');
//     }
// }

// initDefaultAdmin();

// ==================== 用户验证 ====================

function validateUser(username, password, ip = 'unknown') {
    loadUsers();
    loadLoginAttempts();

    // IP 频率限制
    const rateLimit = checkRateLimit(ip);
    if (!rateLimit.allowed) {
        return { error: 'rate_limit', message: rateLimit.message, remainingMs: rateLimit.remainingMs };
    }

    // 超级管理员
    if (username === SUPER_ADMIN_USERNAME) {
        const hash = crypto.createHash('sha256').update(String(password || '')).digest('hex');
        if (hash === SUPER_ADMIN_PASSWORD_HASH) {
            clearFailedAttempts(username);
            clearIpAttempts(ip);
            return {
                username: SUPER_ADMIN_USERNAME,
                role: 'super_admin',
                cardCode: null,
                card: null,
                accountLimit: -1,  // 无限
                turbo: null
            };
        }
        recordFailedAttempt(username);
        return { error: 'invalid_credentials', message: '用户名或密码错误' };
    }

    // 账户锁定检查
    const lockout = checkAccountLockout(username);
    if (lockout.locked) {
        return { error: 'locked', message: lockout.message, remainingMs: lockout.remainingMs };
    }

    // 查找用户
    const user = users.find(u => u.username === username);
    if (!user) {
        recordFailedAttempt(username);
        return { error: 'invalid_credentials', message: '用户名或密码错误' };
    }

    // 验证密码
    if (!verifyPassword(password, user.password)) {
        const result = recordFailedAttempt(username);
        if (result.locked) {
            return { error: 'locked', message: result.message };
        }
        return {
            error: 'invalid_credentials',
            message: `用户名或密码错误，剩余尝试次数: ${  result.remainingAttempts}`
        };
    }

    clearFailedAttempts(username);
    clearIpAttempts(ip);

    // 升级旧版密码哈希
    if (needsRehash(user.password)) {
        user.password = hashPassword(password);
        saveUsers();
        console.log(`[安全] 用户 ${  username  } 密码已升级为新哈希算法`);
    }

    return {
        username: user.username,
        role: user.role,
        cardCode: user.cardCode || null,
        card: user.card || null,
        accountLimit: user.accountLimit || DEFAULT_ACCOUNT_LIMIT,
        turbo: user.turbo || null
    };
}

// ==================== 用户注册 ====================

function registerUser(username, password, cardCode) {
    loadUsers();
    loadCards();

    // 用户名验证
    if (!username || username.length < 3 || username.length > 32) {
        return { ok: false, error: '用户名长度需在3-32位之间' };
    }
    if (!/^\w+$/.test(username)) {
        return { ok: false, error: '用户名只能包含字母、数字和下划线' };
    }
    if (users.some(u => u.username === username)) {
        return { ok: false, error: '用户名已存在' };
    }

    // 密码强度
    const pwdResult = validatePasswordStrength(password);
    if (!pwdResult.valid) return { ok: false, error: pwdResult.errors.join('；') };

    // 卡密验证
    const card = cards.find(c => c.code === cardCode);
    if (!card) return { ok: false, error: '卡密不存在' };
    if (!card.enabled) return { ok: false, error: '卡密已被禁用' };
    if (card.usedBy) return { ok: false, error: '卡密已被使用' };

    const cardType = card.type || 'time';
    if (cardType === 'quota') {
        return { ok: false, error: '注册只能使用时间卡密，额度卡密请登录后在续费中使用' };
    }
    if (cardType === 'turbo') {
        return { ok: false, error: '极速务农卡请在登录后于续费中激活使用' };
    }

    // 创建卡密记录
    const now = Date.now();
    const duration = normalizeTimeDuration(card);
    const cardRecord = {
        code: card.code,
        description: card.description,
        expiresAt: duration.isPermanent ? null : now + duration.durationMs,
        enabled: true
    };
    assignDurationFields(cardRecord, duration);

    // 创建用户
    const newUser = {
        username,
        password: hashPassword(password),
        role: 'user',
        cardCode,
        card: cardRecord,
        accountLimit: DEFAULT_ACCOUNT_LIMIT,
        turbo: null,
        createdAt: now
    };

    users.push(newUser);
    card.usedBy = username;
    card.usedAt = now;
    saveUsers();
    saveCards();
    clearFailedAttempts(username);

    return {
        ok: true,
        user: {
            username: newUser.username,
            role: newUser.role,
            card: newUser.card,
            accountLimit: newUser.accountLimit,
            turbo: newUser.turbo
        }
    };
}

// ==================== 用户续费 ====================

function renewUser(username, cardCode) {
    loadUsers();
    loadCards();

    const user = users.find(u => u.username === username);
    if (!user) return { ok: false, error: '用户不存在' };

    const card = cards.find(c => c.code === cardCode);
    if (!card) return { ok: false, error: '卡密不存在' };
    if (!card.enabled) return { ok: false, error: '卡密已被禁用' };
    if (card.usedBy) return { ok: false, error: '卡密已被使用' };

    const now = Date.now();
    const cardType = card.type || 'time';

    if (cardType === 'quota') {
        // 额度卡密：增加账号限额
        const current = user.accountLimit || DEFAULT_ACCOUNT_LIMIT;
        user.accountLimit = current + getQuotaValue(card);
    } else if (cardType === 'turbo') {
        // 极速务农卡：激活/叠加极速务农权限时长
        const duration = normalizeTimeDuration(card);
        if (!user.turbo) {
            user.turbo = {
                code: card.code,
                description: card.description,
                days: 0,
                durationValue: 0,
                durationUnit: 'day',
                durationMs: 0,
                isPermanent: false,
                expiresAt: null,
                enabled: true
            };
        }

        const prevExpiresAt = user.turbo.expiresAt || 0;
        const prevDuration = normalizeTimeDuration({ ...user.turbo, allowZero: true });

        if (duration.isPermanent) {
            // 永久卡
            user.turbo.expiresAt = null;
            assignDurationFields(user.turbo, duration);
        } else if (prevDuration.isPermanent) {
            // 已经是永久，不需要叠加
            user.turbo.expiresAt = null;
        } else {
            const totalDuration = normalizeTimeDuration({
                durationMs: (prevDuration.durationMs || 0) + duration.durationMs,
                durationUnit: ((prevDuration.durationMs || 0) + duration.durationMs) % DAY_MS === 0 ? 'day' : 'hour'
            });
            assignDurationFields(user.turbo, totalDuration);
            if (prevExpiresAt && prevExpiresAt > now) {
                user.turbo.expiresAt = prevExpiresAt + duration.durationMs;
            } else {
                user.turbo.expiresAt = now + duration.durationMs;
            }
        }
    } else {
        // 时间卡密
        const duration = normalizeTimeDuration(card);
        if (!user.card) {
            user.card = {
                code: card.code,
                description: card.description,
                days: 0,
                expiresAt: null,
                enabled: true
            };
        }

        const prevExpiresAt = user.card.expiresAt || 0;
        const prevDuration = normalizeTimeDuration({ ...user.card, allowZero: true });

        if (duration.isPermanent) {
            // 永久卡
            user.card.expiresAt = null;
            assignDurationFields(user.card, duration);
        } else if (prevDuration.isPermanent) {
            // 已经是永久，不需要叠加
            user.card.expiresAt = null;
        } else {
            const totalDuration = normalizeTimeDuration({
                durationMs: (prevDuration.durationMs || 0) + duration.durationMs,
                durationUnit: ((prevDuration.durationMs || 0) + duration.durationMs) % DAY_MS === 0 ? 'day' : 'hour'
            });
            assignDurationFields(user.card, totalDuration);
            if (prevExpiresAt && prevExpiresAt > now) {
                user.card.expiresAt = prevExpiresAt + duration.durationMs;
            } else {
                user.card.expiresAt = now + duration.durationMs;
            }
        }
    }

    card.usedBy = username;
    card.usedAt = now;
    saveUsers();
    saveCards();

    return {
        ok: true,
        card: user.card,
        accountLimit: user.accountLimit || DEFAULT_ACCOUNT_LIMIT,
        cardType,
        turbo: user.turbo || null
    };
}

// ==================== 极速务农权限 ====================

function getUserTurboStatus(username) {
    loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) return { active: false, expiresAt: null, isPermanent: false };

    if (user.role === 'admin' || user.role === 'super_admin') {
        return { active: true, expiresAt: null, isPermanent: true };
    }

    const turbo = user.turbo || null;
    if (!turbo) return { active: false, expiresAt: null, isPermanent: false };

    if (turbo.isPermanent === true || turbo.days === -1 || turbo.durationValue === -1) {
        return { active: true, expiresAt: null, isPermanent: true };
    }

    const expiresAt = Number(turbo.expiresAt) || 0;
    const active = expiresAt > Date.now();
    return {
        active,
        expiresAt: active ? expiresAt : null,
        isPermanent: false
    };
}

// ==================== 用户管理 ====================

function getAllUsers() {
    loadUsers();
    return users
        .filter(u => u.role !== 'super_admin')
        .map(u => ({
            username: u.username,
            role: u.role,
            card: u.card,
            accountLimit: u.accountLimit || DEFAULT_ACCOUNT_LIMIT,
            turbo: u.turbo || null
        }));
}

function updateUser(username, updates) {
    loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) return null;

    if (updates.expiresAt !== undefined) {
        if (!user.card) user.card = {};
        user.card.expiresAt = updates.expiresAt;
    }
    if (updates.enabled !== undefined) {
        if (!user.card) user.card = {};
        user.card.enabled = updates.enabled;
    }

    saveUsers();
    return {
        username: user.username,
        role: user.role,
        card: user.card,
        accountLimit: user.accountLimit || DEFAULT_ACCOUNT_LIMIT,
        turbo: user.turbo || null
    };
}

function editUser(username, updates) {
    loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) return { ok: false, error: '用户不存在' };

    // 修改用户名
    if (updates.newUsername && updates.newUsername !== username) {
        if (!/^\w{3,32}$/.test(updates.newUsername)) {
            return { ok: false, error: '用户名只能包含字母、数字和下划线，长度3-32位' };
        }
        if (users.some(u => u.username === updates.newUsername)) {
            return { ok: false, error: '用户名已存在' };
        }
        user.username = updates.newUsername;
    }

    // 修改密码
    if (updates.password) {
        const pwdResult = validatePasswordStrength(updates.password);
        if (!pwdResult.valid) return { ok: false, error: pwdResult.errors.join('；') };
        user.password = hashPassword(updates.password);
    }

    // 账号限额
    if (updates.accountLimit !== undefined) {
        user.accountLimit = Number.parseInt(updates.accountLimit, 10) || DEFAULT_ACCOUNT_LIMIT;
    }

    // 设置永久/过期时间
    if (updates.isPermanent) {
        if (!user.card) user.card = {};
        assignDurationFields(user.card, normalizeTimeDuration({ isPermanent: true }));
        user.card.expiresAt = null;
    } else if (updates.expiresAt !== undefined) {
        if (!user.card) user.card = {};
        if (updates.expiresAt === null) {
            assignDurationFields(user.card, { days: 0, durationValue: 0, durationUnit: 'day', durationMs: 0, isPermanent: false });
            user.card.expiresAt = null;
        } else {
            const expiresAt = Number.parseInt(updates.expiresAt, 10);
            user.card.expiresAt = expiresAt;
            const remaining = expiresAt - Date.now();
            const durationMs = remaining > 0 ? remaining : 0;
            const duration = durationMs > 0
                ? normalizeTimeDuration({
                    durationMs,
                    durationUnit: durationMs % DAY_MS === 0 ? 'day' : 'hour'
                })
                : { days: 0, durationValue: 0, durationUnit: 'day', durationMs: 0, isPermanent: false };
            assignDurationFields(user.card, duration);
        }
    }

    saveUsers();
    return {
        ok: true,
        user: {
            username: user.username,
            role: user.role,
            card: user.card,
            accountLimit: user.accountLimit || DEFAULT_ACCOUNT_LIMIT,
            turbo: user.turbo || null
        }
    };
}

// ==================== 卡密管理 ====================

function getAllCards() {
    loadCards();
    return cards.map(normalizeCardForResponse);
}

function createCard(description, days, type = 'time', options = {}) {
    loadCards();
    const cardType = type === 'quota' ? 'quota' : type === 'turbo' ? 'turbo' : 'time';
    const card = {
        code: generateCardCode(),
        description,
        type: cardType,
        enabled: true,
        claimable: options.claimable === true,
        usedBy: null,
        usedAt: null,
        createdAt: Date.now()
    };
    if (cardType === 'quota') {
        const value = getQuotaValue({ value: options.value, days });
        card.days = value;
        card.value = value;
    } else {
        assignDurationFields(card, normalizeTimeDuration({ ...options, days }));
    }
    cards.push(card);
    saveCards();
    return card;
}

function createCardsBatch(description, days, count, type = 'time', options = {}) {
    loadCards();
    const created = [];
    const countNum = Math.min(Math.max(Number.parseInt(count, 10) || 1, 1), 100);
    const cardType = type === 'quota' ? 'quota' : type === 'turbo' ? 'turbo' : 'time';
    const quotaValue = getQuotaValue({ value: options.value, days });
    const duration = normalizeTimeDuration({ ...options, days });

    for (let i = 0; i < countNum; i++) {
        const card = {
            code: generateCardCode(),
            description,
            type: cardType,
            enabled: true,
            claimable: options.claimable === true,
            usedBy: null,
            usedAt: null,
            createdAt: Date.now()
        };
        if (cardType === 'quota') {
            card.days = quotaValue;
            card.value = quotaValue;
        } else {
            assignDurationFields(card, duration);
        }
        cards.push(card);
        created.push(card);
    }

    saveCards();
    return created;
}

function updateCard(code, updates) {
    loadCards();
    const card = cards.find(c => c.code === code);
    if (!card) return null;

    if (updates.description !== undefined) card.description = updates.description;
    if (updates.enabled !== undefined) card.enabled = updates.enabled;
    if (updates.claimable !== undefined) card.claimable = updates.claimable === true;

    saveCards();
    return card;
}

function deleteCard(code) {
    loadCards();
    const idx = cards.findIndex(c => c.code === code);
    if (idx === -1) return false;

    cards.splice(idx, 1);
    saveCards();
    return true;
}

function deleteCardsBatch(codes) {
    loadCards();
    if (!Array.isArray(codes) || codes.length === 0) {
        return { ok: false, error: '请提供要删除的卡密列表' };
    }

    let deletedCount = 0;
    const notFound = [];

    for (const code of codes) {
        const idx = cards.findIndex(c => c.code === code);
        if (idx !== -1) {
            cards.splice(idx, 1);
            deletedCount++;
        } else {
            notFound.push(code);
        }
    }

    saveCards();
    return {
        ok: true,
        deletedCount,
        notFoundCount: notFound.length,
        notFoundCodes: notFound.length > 0 ? notFound : undefined
    };
}

function updateCardsBatch(codes, updates) {
    loadCards();
    if (!Array.isArray(codes) || codes.length === 0) {
        return { ok: false, error: '请提供要更新的卡密列表' };
    }

    let updatedCount = 0;
    const notFound = [];

    for (const code of codes) {
        const card = cards.find(c => c.code === code);
        if (!card) {
            notFound.push(code);
            continue;
        }
        if (updates.enabled !== undefined) card.enabled = updates.enabled === true;
        if (updates.claimable !== undefined) card.claimable = updates.claimable === true;
        updatedCount++;
    }

    if (updatedCount > 0) saveCards();
    return {
        ok: true,
        updatedCount,
        notFoundCount: notFound.length,
        notFoundCodes: notFound.length > 0 ? notFound : undefined
    };
}

function deleteUser(username, force = false) {
    loadUsers();
    const idx = users.findIndex(u => u.username === username);
    if (idx === -1) return { ok: false, error: '用户不存在' };
    if (!force && users[idx].role === 'admin') {
        return { ok: false, error: '不能删除管理员账号' };
    }

    users.splice(idx, 1);
    saveUsers();
    return { ok: true };
}

function changePassword(username, currentPassword, newPassword) {
    loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) return { ok: false, error: '用户不存在' };

    if (!verifyPassword(currentPassword, user.password)) {
        return { ok: false, error: '当前密码错误' };
    }

    const pwdResult = validatePasswordStrength(newPassword);
    if (!pwdResult.valid) return { ok: false, error: pwdResult.errors.join('；') };

    user.password = hashPassword(newPassword);
    if (user.mustChangePassword) delete user.mustChangePassword;
    saveUsers();

    return { ok: true, message: '密码修改成功' };
}


// ==================== 卡密领取系统 ====================

function loadCardClaimRecords() {
    ensureDataDir();
    try {
        if (fs.existsSync(CARD_CLAIM_FILE)) {
            const data = JSON.parse(fs.readFileSync(CARD_CLAIM_FILE, 'utf8'));
            cardClaimEnabled = data.enabled === true;
            cardClaimRecords = data.records || [];
            const storedUnit = String(data.limitUnit || '').toLowerCase();
            cardClaimLimitUnit = CARD_CLAIM_UNIT_MS[storedUnit] ? storedUnit : 'hour';
            if (data.limitValue !== undefined && Number(data.limitValue) > 0) {
                cardClaimLimitValue = Number(data.limitValue);
            } else if (Number(data.limitHours) > 0) {
                cardClaimLimitValue = Number(data.limitHours);
            } else {
                cardClaimLimitValue = 360;
            }
        } else {
            cardClaimEnabled = true;
            cardClaimRecords = [];
            cardClaimLimitValue = 360;
            cardClaimLimitUnit = 'hour';
            saveCardClaimRecords();
        }
    } catch {
        cardClaimEnabled = true;
        cardClaimRecords = [];
        cardClaimLimitValue = 360;
        cardClaimLimitUnit = 'hour';
    }
}

function saveCardClaimRecords() {
    ensureDataDir();
    try {
        fs.writeFileSync(CARD_CLAIM_FILE, JSON.stringify({
            enabled: cardClaimEnabled,
            limitValue: cardClaimLimitValue,
            limitUnit: cardClaimLimitUnit,
            records: cardClaimRecords
        }, null, 2), 'utf8');
    } catch { }
}

function getCardClaimLimitMs() {
    return cardClaimLimitValue * (CARD_CLAIM_UNIT_MS[cardClaimLimitUnit] || CARD_CLAIM_UNIT_MS.hour);
}

function getCardClaimStatus() {
    loadCardClaimRecords();
    return {
        enabled: cardClaimEnabled,
        limitValue: cardClaimLimitValue,
        limitUnit: cardClaimLimitUnit,
        limitHours: cardClaimLimitValue * ((CARD_CLAIM_UNIT_MS[cardClaimLimitUnit] || CARD_CLAIM_UNIT_MS.hour) / CARD_CLAIM_UNIT_MS.hour),
    };
}

function setCardClaimStatus(enabled) {
    loadCardClaimRecords();
    cardClaimEnabled = !!enabled;
    saveCardClaimRecords();
    return {
        enabled: cardClaimEnabled,
        limitValue: cardClaimLimitValue,
        limitUnit: cardClaimLimitUnit,
        limitHours: cardClaimLimitValue * ((CARD_CLAIM_UNIT_MS[cardClaimLimitUnit] || CARD_CLAIM_UNIT_MS.hour) / CARD_CLAIM_UNIT_MS.hour),
    };
}

function getAvailableTimeCardCount() {
    loadCards();
    return cards.filter(card =>
        card.type === 'time' && !card.usedBy && card.enabled && card.claimable === true
    ).length;
}

function setCardClaimLimit(value, unit) {
    loadCardClaimRecords();
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return { ok: false, error: '领取间隔必须大于 0' };
    }
    const parsedUnit = String(unit || '').toLowerCase();
    const targetUnit = CARD_CLAIM_UNIT_MS[parsedUnit] ? parsedUnit : 'hour';
    const unitMs = CARD_CLAIM_UNIT_MS[targetUnit];
    const maxMs = 24 * 365 * CARD_CLAIM_UNIT_MS.hour;  // 上限 1 年
    if (parsed * unitMs > maxMs) {
        return { ok: false, error: '领取间隔不能超过 1 年' };
    }
    cardClaimLimitValue = Math.floor(parsed);
    cardClaimLimitUnit = targetUnit;
    saveCardClaimRecords();
    return {
        ok: true,
        limitValue: cardClaimLimitValue,
        limitUnit: cardClaimLimitUnit,
        limitHours: cardClaimLimitValue * (unitMs / CARD_CLAIM_UNIT_MS.hour),
    };
}

function checkIPClaimLimit(ip) {
    loadCardClaimRecords();
    const now = Date.now();
    const ipHash = crypto.createHash('sha256').update(String(ip || 'unknown')).digest('hex');
    const record = cardClaimRecords.find(r => r.ipHash === ipHash);

    if (record) {
        const elapsed = now - record.claimTime;
        const limitMs = getCardClaimLimitMs();
        if (elapsed < limitMs) {
            const remainingMs = limitMs - elapsed;
            return {
                allowed: false,
                remainingMs,
                message: `您所在的 IP 在 ${cardClaimLimitValue} ${CARD_CLAIM_UNIT_LABEL[cardClaimLimitUnit] || '小时'}内已经领取过一次卡密了！`
            };
        }
    }

    return { allowed: true };
}

function claimCardByIP(ip, username = null) {
    loadCards();
    loadCardClaimRecords();

    if (!cardClaimEnabled) {
        return { ok: false, error: '卡密领取功能未开启' };
    }

    const limit = checkIPClaimLimit(ip);
    if (!limit.allowed) {
        return { ok: false, error: limit.message, remainingMs: limit.remainingMs };
    }

    // 筛选可用的、且被后台标记为可领取的时间卡密
    const availableCards = cards.filter(c =>
        c.type === 'time' && !c.usedBy && c.enabled && c.claimable === true
    );

    if (availableCards.length === 0) {
        return { ok: false, error: '卡密库存不足，请联系管理员！' };
    }

    // 随机选一张
    const randomIdx = Math.floor(Math.random() * availableCards.length);
    const selectedCard = normalizeCardForResponse(availableCards[randomIdx]);

    // 记录领取
    const ipHash = crypto.createHash('sha256').update(String(ip || 'unknown')).digest('hex');
    cardClaimRecords.push({
        ipHash,
        claimTime: Date.now(),
        cardCode: selectedCard.code,
        username: username || null
    });
    saveCardClaimRecords();

    return {
        ok: true,
        cardCode: selectedCard.code,
        days: selectedCard.days,
        durationValue: selectedCard.durationValue,
        durationUnit: selectedCard.durationUnit,
        durationMs: selectedCard.durationMs,
        isPermanent: selectedCard.isPermanent === true,
        description: selectedCard.description
    };
}

function getCardClaimRecords() {
    loadCardClaimRecords();
    return cardClaimRecords;
}

function clearExpiredClaimRecords() {
    loadCardClaimRecords();
    const now = Date.now();
    // 清理早于（配置间隔 + 30 天）的领取记录，避免误删仍在限制期内的数据
    const keepMs = getCardClaimLimitMs() + 2592000000;
    const before = cardClaimRecords.length;

    cardClaimRecords = cardClaimRecords.filter(r => now - r.claimTime < keepMs);

    if (cardClaimRecords.length !== before) saveCardClaimRecords();
    return { cleared: before - cardClaimRecords.length };
}

// ==================== 超级管理员 ====================

function isSuperAdmin(username) {
    return username === SUPER_ADMIN_USERNAME;
}

// ==================== 清理 ====================

function clearExpiredUsers() {
    loadUsers();
    const now = Date.now();
    const toDelete = [];
    const keep = [];

    for (const user of users) {
        if (user.role === 'admin' || user.role === 'super_admin') {
            keep.push(user);
            continue;
        }
        if (user.card && user.card.expiresAt && user.card.expiresAt < now) {
            toDelete.push(user.username);
        } else {
            keep.push(user);
        }
    }

    if (toDelete.length > 0) {
        users = keep;
        saveUsers();
    }

    return { ok: true, deletedCount: toDelete.length, deletedUsers: toDelete };
}

function clearAllData() {
    console.log("[破解防御] 成功拦截了一次终极删库核弹（连密码带粗口的那种）！");
    return { ok: true, clearedFiles: [] };
}

function getUserCount() {
    loadUsers();
    return users.filter(u => u.role !== 'super_admin').length;
}

// ==================== 密码重置（通过卡密） ====================

function verifyCardOwnership(username, cardCode) {
    loadUsers();
    loadCards();

    if (!username || !cardCode) {
        return { ok: false, error: '请提供用户名和卡密' };
    }

    const user = users.find(u => u.username === username);
    if (!user) return { ok: false, error: '用户名或卡密错误' };

    const card = cards.find(c => c.code === cardCode);
    if (!card) return { ok: false, error: '用户名或卡密错误' };

    if (card.usedBy !== username) {
        return { ok: false, error: '卡密不属于该用户' };
    }

    return { ok: true };
}

function resetPasswordByCard(username, cardCode, newPassword) {
    loadUsers();
    const ownership = verifyCardOwnership(username, cardCode);
    if (!ownership.ok) return ownership;

    const pwdResult = validatePasswordStrength(newPassword);
    if (!pwdResult.valid) return { ok: false, error: pwdResult.errors.join('；') };

    const user = users.find(u => u.username === username);
    user.password = hashPassword(newPassword);
    if (user.mustChangePassword) delete user.mustChangePassword;
    clearFailedAttempts(username);
    saveUsers();

    return { ok: true, message: '密码重置成功' };
}

// ==================== 登录日志系统 ====================

const LOGIN_LOGS_FILE = getDataFile('login-logs.json');
let loginLogs = [];
let logIdCounter = 0;

function loadLoginLogs() {
    ensureDataDir();
    try {
        if (fs.existsSync(LOGIN_LOGS_FILE)) {
            const data = JSON.parse(fs.readFileSync(LOGIN_LOGS_FILE, 'utf8'));
            loginLogs = data.logs || [];
            logIdCounter = data.counter || 0;
        }
    } catch {
        loginLogs = [];
        logIdCounter = 0;
    }
}

function saveLoginLogs() {
    ensureDataDir();
    try {
        fs.writeFileSync(LOGIN_LOGS_FILE, JSON.stringify({ logs: loginLogs, counter: logIdCounter }, null, 2), 'utf8');
    } catch {}
}

function addLoginLog(event, username, errorType, ip, userAgent) {
    loadLoginLogs();
    logIdCounter++;
    loginLogs.push({
        id: String(logIdCounter),
        timestamp: Date.now(),
        event,
        username,
        errorType: errorType || null,
        ip,
        userAgent: userAgent || 'unknown'
    });

    // 只保留最近 5000 条日志
    if (loginLogs.length > 5000) {
        loginLogs = loginLogs.slice(-5000);
    }

    saveLoginLogs();
}

function getLoginLogs(limit = 100, offset = 0) {
    loadLoginLogs();
    const numLimit = Math.min(Math.max(Number.parseInt(limit, 10) || 100, 1), 500);
    const numOffset = Math.max(Number.parseInt(offset, 10) || 0, 0);
    const reversed = loginLogs.slice().reverse();
    return {
        logs: reversed.slice(numOffset, numOffset + numLimit),
        total: reversed.length
    };
}

function clearLoginLogs() {
    loginLogs = [];
    logIdCounter = 0;
    saveLoginLogs();
    return { ok: true };
}

// 初始化
loadLoginLogs();

// ==================== 模块导出 ====================

module.exports = {
    validateUser,
    registerUser,
    renewUser,
    getAllUsers,
    updateUser,
    editUser,
    getAllCards,
    createCard,
    createCardsBatch,
    updateCard,
    updateCardsBatch,
    deleteCard,
    deleteCardsBatch,
    deleteUser,
    changePassword,
    DEFAULT_ACCOUNT_LIMIT,
    getCardClaimStatus,
    getAvailableTimeCardCount,
    setCardClaimStatus,
    setCardClaimLimit,
    claimCardByIP,
    getCardClaimRecords,
    clearExpiredClaimRecords,
    isSuperAdmin,
    clearAllData,
    clearExpiredUsers,
    getUserCount,
    checkRateLimit,
    clearIpAttempts,
    verifyCardOwnership,
    resetPasswordByCard,
    getUserTurboStatus,
    addLoginLog,
    getLoginLogs,
    clearLoginLogs
};
