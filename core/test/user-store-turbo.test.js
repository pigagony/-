const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qq-farm-user-store-turbo-'));
process.env.FARM_DATA_DIR = dataDir;

const userStore = require('../src/models/user-store');

test.after(() => {
  fs.rmSync(dataDir, { recursive: true, force: true });
});

function makeTurboCard(description, days = 30) {
  return userStore.createCard(description, days, 'turbo', { durationUnit: 'day' });
}

function makeTimeCard(description, days = 30) {
  return userStore.createCard(description, days, 'time', { durationUnit: 'day' });
}

function registerWithTimeCard(username) {
  const card = makeTimeCard(`${username} 注册卡`);
  const result = userStore.registerUser(username, 'Passw0rd!', card.code);
  assert.equal(result.ok, true, `注册 ${username} 失败: ${result.error}`);
  return result;
}

function setRole(username, role) {
  const usersFile = path.join(dataDir, 'users.json');
  const data = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
  const user = data.users.find(u => u.username === username);
  user.role = role;
  fs.writeFileSync(usersFile, JSON.stringify(data, null, 2));
}

test('createCard supports turbo type with duration fields', () => {
  const card = makeTurboCard('极速务农月卡', 30);
  assert.equal(card.type, 'turbo');
  assert.equal(card.days, 30);
  assert.equal(card.durationValue, 30);
  assert.equal(card.durationUnit, 'day');
  assert.equal(card.isPermanent, false);
});

test('createCardsBatch supports turbo type', () => {
  const cards = userStore.createCardsBatch('极速务农批量卡', 7, 3, 'turbo', { durationUnit: 'day' });
  assert.equal(cards.length, 3);
  for (const c of cards) {
    assert.equal(c.type, 'turbo');
    assert.equal(c.days, 7);
  }
});

test('registerUser rejects turbo card', () => {
  const card = makeTurboCard('不可用于注册');
  const result = userStore.registerUser('turbo_reg_user', 'Passw0rd!', card.code);
  assert.equal(result.ok, false);
  assert.match(result.error, /极速务农卡/);
});

test('renewUser with turbo card activates turbo permission', () => {
  registerWithTimeCard('turbo_user1');
  const card = makeTurboCard('极速务农30天', 30);
  const result = userStore.renewUser('turbo_user1', card.code);
  assert.equal(result.ok, true);
  assert.equal(result.cardType, 'turbo');
  assert.ok(result.turbo);
  assert.equal(result.turbo.days, 30);
  assert.ok(result.turbo.expiresAt > Date.now());
});

test('renewUser with turbo card stacks duration', () => {
  registerWithTimeCard('turbo_user4');
  const c1 = makeTurboCard('第一次30天', 30);
  const c2 = makeTurboCard('第二次30天', 30);
  assert.equal(userStore.renewUser('turbo_user4', c1.code).ok, true);
  const before = userStore.renewUser('turbo_user4', c2.code);
  assert.equal(before.ok, true);
  assert.equal(before.turbo.days, 60);
});

test('getUserTurboStatus returns active for valid card', () => {
  const status = userStore.getUserTurboStatus('turbo_user1');
  assert.equal(status.active, true);
  assert.ok(status.expiresAt > Date.now());
});

test('getUserTurboStatus inactive for user without turbo', () => {
  registerWithTimeCard('turbo_user2');
  const status = userStore.getUserTurboStatus('turbo_user2');
  assert.equal(status.active, false);
  assert.equal(status.expiresAt, null);
});

test('getUserTurboStatus permanent for admin role', () => {
  setRole('turbo_user1', 'admin');
  const status = userStore.getUserTurboStatus('turbo_user1');
  assert.equal(status.active, true);
  assert.equal(status.isPermanent, true);
});

test('getAllUsers includes turbo field', () => {
  const users = userStore.getAllUsers();
  const target = users.find(u => u.username === 'turbo_user4');
  assert.ok(target);
  assert.ok('turbo' in target);
  assert.equal(target.turbo.days, 60);
});

test('validateUser returns turbo field', () => {
  const result = userStore.validateUser('turbo_user4', 'Passw0rd!', '127.0.0.1');
  assert.ok(result);
  assert.ok(result.turbo);
  assert.equal(result.turbo.days, 60);
});

test('renewUser with permanent turbo card sets null expiresAt', () => {
  registerWithTimeCard('turbo_user3');
  const card = makeTurboCard('永久极速务农', 0);
  card.days = -1;
  card.durationValue = -1;
  card.isPermanent = true;
  card.expiresAt = null;
  const usersFile = path.join(dataDir, 'cards.json');
  const data = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
  const target = data.cards.find(c => c.code === card.code);
  target.days = -1;
  target.durationValue = -1;
  target.isPermanent = true;
  target.expiresAt = null;
  fs.writeFileSync(usersFile, JSON.stringify(data, null, 2));

  const result = userStore.renewUser('turbo_user3', card.code);
  assert.equal(result.ok, true);
  assert.equal(result.turbo.isPermanent, true);
  assert.equal(result.turbo.expiresAt, null);
  const status = userStore.getUserTurboStatus('turbo_user3');
  assert.equal(status.active, true);
  assert.equal(status.isPermanent, true);
});
