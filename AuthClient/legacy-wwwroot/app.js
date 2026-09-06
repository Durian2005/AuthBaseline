const API_BASE = window.location.origin;

function $(id) { return document.getElementById(id); }

function formatTime(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    return d.toLocaleString('zh-CN');
}

function statusText(status) {
    const map = { Pending: '待审核', Enabled: '启用', Locked: '锁定', Disabled: '禁用' };
    return map[status] || status;
}

function showToast(message, type = 'info') {
    const toast = $('toast');
    toast.textContent = message;
    toast.className = `toast ${type}`;
    setTimeout(() => toast.classList.add('hidden'), 3000);
}

// 统一处理网络异常与非 JSON 响应，避免前端只显示笼统的失败提示
async function request(path, options) {
    try {
        const res = await fetch(`${API_BASE}${path}`, options);
        const text = await res.text();
        let data = {};
        try { data = JSON.parse(text); } catch { data = {}; }
        if (!res.ok && !data.message) {
            data.message = `服务器返回 HTTP ${res.status}`;
        }
        return { ok: res.ok, status: res.status, data };
    } catch (err) {
        return {
            ok: false,
            status: 0,
            data: { success: false, message: '无法连接服务器，请确认后端已启动（http://localhost:5007）' }
        };
    }
}

async function apiPost(path, body) {
    return request(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

async function apiGet(path) {
    return request(path, { method: 'GET' });
}

const app = {
    currentUser: null,
    lockTimer: null,

    init() {
        // 标签切换
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => this.switchTab(btn.dataset.tab));
        });

        $('login-form').addEventListener('submit', e => { e.preventDefault(); this.login(); });
        $('register-form').addEventListener('submit', e => { e.preventDefault(); this.register(); });
        $('change-password-form').addEventListener('submit', e => { e.preventDefault(); this.changePassword(); });
        $('logout-btn').addEventListener('click', () => this.logout());

        const saved = localStorage.getItem('currentUser');
        if (saved) {
            this.currentUser = JSON.parse(saved);
            this.showDashboard();
        }
    },

    switchTab(tab) {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `${tab}-panel`));
    },

    async register() {
        const username = $('register-username').value.trim();
        const password = $('register-password').value;
        const password2 = $('register-password2').value;

        if (!username || !password) {
            showToast('用户名和密码不能为空', 'error');
            return;
        }
        if (password !== password2) {
            showToast('两次输入的密码不一致', 'error');
            return;
        }

        const { ok, data } = await apiPost('/api/auth/register', { username, password });
        if (ok && data.success) {
            showToast(data.message, 'success');
            $('register-form').reset();
            this.switchTab('login');
        } else {
            showToast(data.message || '注册失败', 'error');
        }
    },

    async login() {
        const username = $('login-username').value.trim();
        const password = $('login-password').value;

        const { ok, data } = await apiPost('/api/auth/login', { username, password });
        if (ok && data.success) {
            this.currentUser = {
                username: data.data.username,
                isAdmin: data.data.isAdmin,
                status: data.data.status,
                lockoutEnd: null
            };
            localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
            $('login-form').reset();
            this.showDashboard();
            showToast(data.message, 'success');
        } else {
            // 即使登录失败，也可能因锁定而返回 lockoutEnd，保存以便显示倒计时
            if (data?.data?.lockoutEnd) {
                this.currentUser = { username, isAdmin: false, status: 'Locked', lockoutEnd: data.data.lockoutEnd };
                localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
                this.showDashboard();
            }
            showToast(data.message || '登录失败', 'error');
        }
    },

    logout() {
        this.currentUser = null;
        localStorage.removeItem('currentUser');
        clearInterval(this.lockTimer);
        $('auth-section').classList.remove('hidden');
        $('user-section').classList.add('hidden');
        $('admin-section').classList.add('hidden');
    },

    showDashboard() {
        $('auth-section').classList.add('hidden');
        $('user-section').classList.remove('hidden');
        $('current-user').textContent = this.currentUser.username;
        this.updateStatusBadge(this.currentUser.status, this.currentUser.lockoutEnd);

        if (this.currentUser.isAdmin) {
            $('admin-section').classList.remove('hidden');
            this.refreshAdmin();
        } else {
            $('admin-section').classList.add('hidden');
        }

        // 定时刷新当前用户状态（锁定倒计时）
        this.refreshCurrentStatus();
        if (this.lockTimer) clearInterval(this.lockTimer);
        this.lockTimer = setInterval(() => this.refreshCurrentStatus(), 1000);
    },

    updateStatusBadge(status, lockoutEnd) {
        const badge = $('user-status');
        badge.className = `status-badge status-${status}`;
        badge.textContent = statusText(status);

        const timer = $('lock-timer');
        if (status === 'Locked' && lockoutEnd) {
            const end = new Date(lockoutEnd).getTime();
            const now = Date.now();
            const sec = Math.max(0, Math.ceil((end - now) / 1000));
            timer.textContent = `锁定剩余 ${sec} 秒`;
            timer.classList.remove('hidden');
        } else {
            timer.classList.add('hidden');
        }
    },

    async refreshCurrentStatus() {
        if (!this.currentUser) return;

        // 更新锁定倒计时
        this.updateStatusBadge(this.currentUser.status, this.currentUser.lockoutEnd);

        // 锁定结束后自动清状态（前端侧），提示重新登录
        if (this.currentUser.status === 'Locked' && this.currentUser.lockoutEnd) {
            const end = new Date(this.currentUser.lockoutEnd).getTime();
            if (Date.now() >= end) {
                this.currentUser.status = 'Enabled';
                this.currentUser.lockoutEnd = null;
                localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
                this.updateStatusBadge('Enabled', null);
                showToast('锁定时间已到，请重新登录', 'info');
                setTimeout(() => this.logout(), 2000);
            }
        }
    },

    async refreshAdmin() {
        if (!this.currentUser?.isAdmin) return;
        const { data } = await apiGet(`/api/auth/users?adminUsername=${encodeURIComponent(this.currentUser.username)}`);
        if (data.success) {
            this.renderUsers(data.data);
        }
        this.refreshLogs();
    },

    renderUsers(users) {
        // 如果当前用户在列表中，同步更新前端状态显示
        const me = users.find(u => u.username === this.currentUser?.username);
        if (me) {
            this.currentUser.status = me.status;
            this.currentUser.lockoutEnd = me.lockoutEnd;
            localStorage.setItem('currentUser', JSON.stringify(this.currentUser));
            this.updateStatusBadge(me.status, me.lockoutEnd);
        }

        const pending = users.filter(u => u.status === 'Pending');
        const tbodyPending = $('pending-users');
        tbodyPending.innerHTML = pending.map(u => `
            <tr>
                <td>${u.username}</td>
                <td>${formatTime(u.createdAt)}</td>
                <td><button class="btn btn-success btn-small" onclick="app.approve('${u.username}')">通过</button></td>
            </tr>
        `).join('') || '<tr><td colspan="3" class="text-center">无待审核用户</td></tr>';

        const tbodyAll = $('all-users');
        tbodyAll.innerHTML = users.map(u => `
            <tr>
                <td>${u.username}</td>
                <td><span class="status-badge status-${u.status}">${statusText(u.status)}</span></td>
                <td>${u.failedLoginAttempts}</td>
                <td>${formatTime(u.lockoutEnd)}</td>
                <td>${u.isAdmin ? '-' : `
                    ${u.status === 'Locked' ? `<button class="btn btn-warning btn-small" onclick="app.unlock('${u.username}')">解锁</button>` : ''}
                    <button class="btn btn-danger btn-small" onclick="app.deleteUser('${u.username}')">注销</button>
                `}</td>
            </tr>
        `).join('') || '<tr><td colspan="5">无用户</td></tr>';
    },

    async refreshLogs() {
        const { data } = await apiGet(`/api/auth/logs?adminUsername=${encodeURIComponent(this.currentUser.username)}`);
        if (data.success) {
            const tbody = $('audit-logs');
            tbody.innerHTML = data.data.map(log => `
                <tr>
                    <td>${formatTime(log.timestamp)}</td>
                    <td>${log.operatorName}</td>
                    <td>${log.action}</td>
                    <td>${log.statusBefore}</td>
                    <td>${log.statusAfter}</td>
                    <td title="${this.escape(log.request || '')}">${this.truncate(log.request || '')}</td>
                    <td title="${this.escape(log.response || '')}">${this.truncate(log.response || '')}</td>
                </tr>
            `).join('');
        }
    },

    async approve(username) {
        const { ok, data } = await apiPost('/api/auth/approve', {
            username,
            adminUsername: this.currentUser.username
        });
        showToast(data.message, ok && data.success ? 'success' : 'error');
        this.refreshAdmin();
    },

    async unlock(username) {
        const { ok, data } = await apiPost('/api/auth/unlock', {
            username,
            adminUsername: this.currentUser.username
        });
        showToast(data.message, ok && data.success ? 'success' : 'error');
        this.refreshAdmin();
    },

    async deleteUser(username) {
        if (!confirm(`确定要注销用户「${username}」吗？\n此操作会永久删除该账号，且不可恢复。`)) {
            return;
        }
        const { ok, data } = await apiPost('/api/auth/delete-user', {
            username,
            adminUsername: this.currentUser.username
        });
        showToast(data.message, ok && data.success ? 'success' : 'error');
        this.refreshAdmin();
    },

    async changePassword() {
        const oldPassword = $('old-password').value;
        const newPassword = $('new-password').value;
        const newPassword2 = $('new-password2').value;

        if (!oldPassword || !newPassword) {
            showToast('密码不能为空', 'error');
            return;
        }
        if (newPassword !== newPassword2) {
            showToast('两次输入的新密码不一致', 'error');
            return;
        }

        const { ok, data } = await apiPost('/api/auth/change-password', {
            username: this.currentUser.username,
            oldPassword,
            newPassword
        });
        if (ok && data.success) {
            showToast(data.message, 'success');
            $('change-password-form').reset();
            this.logout();
        } else {
            showToast(data.message || '修改失败', 'error');
        }
    },

    escape(html) {
        return html.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    },

    truncate(str, len = 80) {
        return str.length > len ? str.slice(0, len) + '…' : str;
    }
};

app.init();
