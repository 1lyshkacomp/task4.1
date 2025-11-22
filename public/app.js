// Элементы
const regForm = document.getElementById('regForm');
const loginForm = document.getElementById('loginForm');
const regCard = document.getElementById('register-card');
const loginCard = document.getElementById('login-card');
const profileEdit = document.getElementById('profile-edit');

document.getElementById('showLogin').addEventListener('click', (e) => {
  e.preventDefault();
  regCard.classList.add('hidden');
  loginCard.classList.remove('hidden');
});

// Регистрация
regForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = {
    nickname: document.getElementById('regNick').value.trim(),
    firstName: document.getElementById('regName').value.trim(),
    lastName: document.getElementById('regLast').value.trim(),
    password: document.getElementById('regPass').value
  };
  try {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const result = await res.json();
    if (res.ok) {
      alert('Успешно! Теперь войдите.');
      regCard.classList.add('hidden');
      loginCard.classList.remove('hidden');
    } else {
      alert(result.error || JSON.stringify(result));
    }
  } catch (err) {
    alert('Ошибка сети');
    console.error(err);
  }
});

// Auth header хранится в sessionStorage, чтобы пережить reload вкладки
let authHeader = sessionStorage.getItem('authHeader') || null;

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const nick = document.getElementById('loginNick').value.trim();
  const pass = document.getElementById('loginPass').value;

  const credentials = btoa(`${nick}:${pass}`);
  authHeader = `Basic ${credentials}`;
  sessionStorage.setItem('authHeader', authHeader);

  try {
    const res = await fetch('/api/me', {
      method: 'GET',
      headers: { 'Authorization': authHeader }
    });
    if (res.ok) {
      const data = await res.json();
      alert(`Привет, ${data.user.firstName}!`);
      loginForm.classList.add('hidden');
      profileEdit.classList.remove('hidden');
      document.getElementById('editName').value = data.user.firstName;
      document.getElementById('editLast').value = data.user.lastName;
    } else {
      const err = await res.json();
      alert(err.error || 'Неверный логин или пароль');
      authHeader = null;
      sessionStorage.removeItem('authHeader');
    }
  } catch (err) {
    alert('Ошибка сети');
    console.error(err);
  }
});

// Обновление данных
document.getElementById('saveBtn').addEventListener('click', async () => {
  if (!authHeader) return alert('Вы не авторизованы');
  const updateData = {
    firstName: document.getElementById('editName').value.trim(),
    lastName: document.getElementById('editLast').value.trim()
  };
  try {
    const res = await fetch('/api/update', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
      body: JSON.stringify(updateData)
    });
    if (res.ok) {
      alert('Данные обновлены!');
    } else {
      const err = await res.json();
      alert(err.error || JSON.stringify(err));
    }
  } catch (err) {
    alert('Ошибка сети');
    console.error(err);
  }
});

// Смена пароля (быстрый prompt; для продакшна используйте модальное окно)
document.getElementById('changePassBtn').addEventListener('click', async () => {
  if (!authHeader) return alert('Вы не авторизованы');
  const oldPassword = prompt('Введите старый пароль:');
  if (!oldPassword) return alert('Отмена');
  const newPassword = prompt('Введите новый пароль (минимум 8 символов):');
  if (!newPassword) return alert('Отмена');

  try {
    const res = await fetch('/api/change-password', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
      body: JSON.stringify({ oldPassword, newPassword })
    });
    const result = await res.json();
    if (res.ok) {
      alert('Пароль изменён');
    } else {
      alert(result.error || JSON.stringify(result));
    }
  } catch (err) {
    alert('Ошибка сети');
    console.error(err);
  }
});

// Выход
document.getElementById('logoutBtn').addEventListener('click', () => {
  authHeader = null;
  sessionStorage.removeItem('authHeader');
  profileEdit.classList.add('hidden');
  loginForm.classList.remove('hidden');
  document.getElementById('loginPass').value = '';
});
