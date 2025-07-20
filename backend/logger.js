const db = require('./mysql') // MySQL 연결

async function logAction(userId, action, ip) {
  try {
    await db
      .promise()
      .query('INSERT INTO logs (user_id, action, ip) VALUES (?, ?, ?)', [
        userId,
        action,
        ip,
      ]) //logs 테이블에 insert
  } catch (err) {
    console.error('로그 저장 실패:', err)
  }
}

module.exports = logAction
