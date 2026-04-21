// UI Helper Functions
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if(!toast) return;
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    setTimeout(() => {
        toast.className = `toast ${type}`;
    }, 4000);
}

function switchForm(formName) {
    document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
    document.getElementById(`${formName}-form`).classList.add('active');
    
    const titles = {
        'login': 'Вход в систему',
        'register': 'Создание аккаунта',
        'recover': 'Восстановление',
        'reset': 'Новый пароль'
    };
    document.getElementById('form-title').textContent = titles[formName];
}

// API Calls
async function apiCall(endpoint, method = 'POST', data = null) {
    try {
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' }
        };
        if (data) options.body = JSON.stringify(data);

        const res = await fetch(endpoint, options);
        const result = await res.json();

        if (!res.ok) {
            throw new Error(result.error || 'Произошла ошибка');
        }
        return result;
    } catch (error) {
        showToast(error.message, 'error');
        throw error;
    }
}

// Auth Handlers
if (document.getElementById('login-form')) {
    
    // Auto-check auth
    fetch('/api/me').then(res => {
        if(res.ok) window.location.href = '/dashboard.html';
    });

    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        try {
            const res = await apiCall('/api/login', 'POST', { username, password });
            showToast(res.message, 'success');
            setTimeout(() => {
                window.location.href = '/dashboard.html';
            }, 1000);
        } catch (e) { }
    });

    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('reg-username').value;
        const password = document.getElementById('reg-password').value;
        const role = document.getElementById('reg-role').value;

        try {
            const res = await apiCall('/api/register', 'POST', { username, password, role });
            showToast(res.message, 'success');
            setTimeout(() => switchForm('login'), 1500);
        } catch (e) { }
    });

    document.getElementById('recover-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('rec-username').value;

        try {
            const res = await apiCall('/api/recover', 'POST', { username });
            showToast(res.message, 'success');
            
            // For the lab, auto-fill token if returned
            if(res.token) {
                document.getElementById('reset-token').value = res.token;
            }
            document.getElementById('reset-username').value = username;
            
            setTimeout(() => switchForm('reset'), 1500);
        } catch (e) { }
    });

    document.getElementById('reset-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('reset-username').value;
        const token = document.getElementById('reset-token').value;
        const newPassword = document.getElementById('reset-password').value;

        try {
            const res = await apiCall('/api/reset', 'POST', { username, token, newPassword });
            showToast(res.message, 'success');
            setTimeout(() => switchForm('login'), 1500);
        } catch (e) { }
    });
}
