# 📚 Standards (行业标准参考库)

> 独立于框架的行业安全标准，作为知识库的外部引用。

---

## 📋 目录结构

```
standards/
├── owasp-top10/           # OWASP Top10 安全标准
├── mitre-attack/          # MITRE ATT&CK 战术与技术框架
└── index.json            # 标准索引
```

---

## 🔗 行业标准

### OWASP Top10
**路径**: `standards/owasp-top10/`
**描述**: Web 应用安全十大风险
**来源**: https://github.com/OWASP/Top10

### MITRE ATT&CK
**路径**: `standards/mitre-attack/`
**描述**: 对抗性战术、技术和常识
**来源**: https://attack.mitre.org/

**子目录**:
- `index.json` - ATT&CK 战术与技术索引
- `navigator-layers/` - Navigator Layer 可视化配置
- `techniques/` - 技术详情 (待填充)
- `tactics/` - 战术详情 (待填充)

---

## 📊 标准索引

```json
{
  "owasp_top10": {
    "version": "2021",
    "url": "standards/owasp-top10/2021"
  },
  "mitre_attack": {
    "version": "v15.1",
    "url": "standards/mitre-attack/"
  }
}
```

---

## 🔄 更新机制

这些标准通过 `git submodule` 独立管理，跟踪上游更新：

```bash
# 更新 OWASP
cd standards/owasp-top10 && git pull

# 更新 ATT&CK
cd standards/mitre-attack && git pull
```

或通过 `submodule-sync.yml` 自动同步。

---

## 💡 使用方式

**Agent 调用示例**:

```
当分析 Web 漏洞时:
  → 参考 OWASP Top10 2021 对应风险类别

当设计攻击链时:
  → 参考 MITRE ATT&CK 战术与技术映射
```

---

*此目录存放行业标准参考，不直接修改*
