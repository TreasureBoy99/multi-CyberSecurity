"""
Mission Orchestrator for multi-CyberSecurity
Coordinates multi-agent security operations

增强特性:
- 多级预算控制 (Campaign + Per-Agent)
- 软阈值警告
- 预算超支处理 (partial report)
"""

import os
import json
import re
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# 默认配置
DEFAULT_MAX_HOURS = 8.0
DEFAULT_MAX_TOKENS = 100000
DEFAULT_PER_AGENT_MAX_TOKENS = 20000
DEFAULT_PER_AGENT_WARN_TOKENS = 15000
DEFAULT_BUDGET_CHECK_INTERVAL = 5


class BudgetController:
    """
    多级预算控制器

    支持:
    - Campaign 级别总预算
    - Per-Agent 独立预算 (防止单一Agent耗尽)
    - 软阈值警告 (50%, 80%)
    - 硬限制超支处理
    """

    def __init__(
        self,
        max_hours: float = DEFAULT_MAX_HOURS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        per_agent_max: int = DEFAULT_PER_AGENT_MAX_TOKENS,
        per_agent_warn: int = DEFAULT_PER_AGENT_WARN_TOKENS,
    ):
        self.max_hours = max_hours
        self.max_tokens = max_tokens
        self.per_agent_max = per_agent_max
        self.per_agent_warn = per_agent_warn

        self._hours_used = 0.0
        self._tokens_used = 0
        self._agent_budgets: Dict[str, Dict] = {}
        self._warnings_issued: set = set()

    def get_campaign_budget(self) -> Dict[str, Any]:
        """获取 Campaign 级别预算状态"""
        return {
            "max_hours": self.max_hours,
            "max_tokens": self.max_tokens,
            "hours_used": self._hours_used,
            "tokens_used": self._tokens_used,
            "hours_remaining": max(0, self.max_hours - self._hours_used),
            "tokens_remaining": max(0, self.max_tokens - self._tokens_used),
            "hours_pct": (self._hours_used / self.max_hours * 100) if self.max_hours > 0 else 0,
            "tokens_pct": (self._tokens_used / self.max_tokens * 100) if self.max_tokens > 0 else 0,
        }

    def get_agent_budget(self, agent_name: str) -> Dict[str, Any]:
        """获取 Per-Agent 预算状态"""
        if agent_name not in self._agent_budgets:
            self._agent_budgets[agent_name] = {
                "max_tokens": self.per_agent_max,
                "warn_at_tokens": self.per_agent_warn,
                "tokens_used": 0,
                "warned_50": False,
                "warned_80": False,
            }
        return self._agent_budgets[agent_name]

    def check_campaign_budget(self, delta_hours: float = 0, delta_tokens: int = 0) -> tuple[bool, str]:
        """
        检查 Campaign 预算是否足够

        Returns:
            (can_proceed, reason)
        """
        new_hours = self._hours_used + delta_hours
        new_tokens = self._tokens_used + delta_tokens

        if self.max_hours > 0 and new_hours > self.max_hours:
            return False, f"Campaign hours budget exceeded: {new_hours:.2f}/{self.max_hours}"
        if self.max_tokens > 0 and new_tokens > self.max_tokens:
            return False, f"Campaign token budget exceeded: {new_tokens}/{self.max_tokens}"

        return True, "OK"

    def check_agent_budget(self, agent_name: str, delta_tokens: int = 0) -> tuple[bool, str]:
        """
        检查 Per-Agent 预算是否足够

        Returns:
            (can_proceed, reason)
        """
        agent = self.get_agent_budget(agent_name)
        new_tokens = agent["tokens_used"] + delta_tokens

        if agent["max_tokens"] > 0 and new_tokens > agent["max_tokens"]:
            return False, f"Agent {agent_name} token budget exceeded: {new_tokens}/{agent['max_tokens']}"

        return True, "OK"

    def update_campaign(self, delta_hours: float, delta_tokens: int):
        """更新 Campaign 预算使用"""
        self._hours_used += delta_hours
        self._tokens_used += delta_tokens

    def update_agent(self, agent_name: str, delta_tokens: int):
        """更新 Per-Agent 预算使用"""
        agent = self.get_agent_budget(agent_name)
        agent["tokens_used"] += delta_tokens

    def check_warnings(self, agent_name: str = None) -> List[Dict]:
        """检查是否需要发出警告"""
        warnings = []

        # Campaign 级别警告
        hours_pct = (self._hours_used / self.max_hours * 100) if self.max_hours > 0 else 0
        tokens_pct = (self._tokens_used / self.max_tokens * 100) if self.max_tokens > 0 else 0

        key_50 = "campaign_50"
        key_80 = "campaign_80"

        if hours_pct >= 50 and key_50 not in self._warnings_issued:
            warnings.append({
                "level": "warning",
                "source": "campaign",
                "threshold": "50%",
                "message": f"Campaign budget at 50%: {hours_pct:.1f}% hours, {tokens_pct:.1f}% tokens",
            })
            self._warnings_issued.add(key_50)

        if hours_pct >= 80 and key_80 not in self._warnings_issued:
            warnings.append({
                "level": "critical",
                "source": "campaign",
                "threshold": "80%",
                "message": f"Campaign budget at 80%: {hours_pct:.1f}% hours, {tokens_pct:.1f}% tokens",
            })
            self._warnings_issued.add(key_80)

        # Per-Agent 警告
        if agent_name:
            agent = self.get_agent_budget(agent_name)
            tokens_pct = (agent["tokens_used"] / agent["max_tokens"] * 100) if agent["max_tokens"] > 0 else 0

            warn_key = f"{agent_name}_50"
            if tokens_pct >= 50 and warn_key not in self._warnings_issued:
                warnings.append({
                    "level": "warning",
                    "source": "agent",
                    "agent": agent_name,
                    "threshold": "50%",
                    "message": f"Agent {agent_name} budget at 50%: {tokens_pct:.1f}%",
                })
                self._warnings_issued.add(warn_key)

        return warnings

    def should_generate_partial_report(self) -> bool:
        """检查是否应该生成部分报告 (预算耗尽时)"""
        return (
            (self.max_hours > 0 and self._hours_used >= self.max_hours) or
            (self.max_tokens > 0 and self._tokens_used >= self.max_tokens)
        )


class MissionOrchestrator:
    """Orchestrates security missions with multi-agent coordination"""

    def __init__(
        self,
        mission_file: str = "framework/MISSION_CONTROL.md",
        max_hours: float = DEFAULT_MAX_HOURS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ):
        self.mission_file = mission_file
        self.campaign_id = uuid.uuid4()

        # 多级预算控制器
        self.budget_controller = BudgetController(
            max_hours=max_hours,
            max_tokens=max_tokens,
        )

        self.mission_data = {
            "project_name": "",
            "target": "",
            "start_time": "",
            "current_stage": "",
            "tasks": [],
            "findings": [],
            "agents": [],
            "budget": {
                "allocated": 0.0,
                "spent": 0.0
            }
        }
        self._ensure_framework_dir()
    
    def _ensure_framework_dir(self):
        """Ensure framework directory exists"""
        framework_dir = os.path.dirname(self.mission_file)
        if framework_dir and not os.path.exists(framework_dir):
            os.makedirs(framework_dir, exist_ok=True)
    
    def initialize_mission(self, project_name: str, target: str, mission_type: str = "web") -> str:
        """
        Initialize a new security mission
        
        Args:
            project_name: Name of the project/mission
            target: Target URL/IP to assess
            mission_type: Type of mission (web, mobile, code-audit, etc.)
        
        Returns:
            Mission ID string
        """
        mission_id = f"mission_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.mission_data = {
            "mission_id": mission_id,
            "project_name": project_name,
            "target": target,
            "mission_type": mission_type,
            "start_time": datetime.now().isoformat(),
            "current_stage": "Recon",
            "status": "active",
            "tasks": [],
            "findings": [],
            "agents": [],
            "budget": {
                "allocated": 0.0,
                "spent": 0.0
            }
        }
        
        content = f"""# 🕹️ 任务控制台 (Mission Control)

## 基本信息
| 字段 | 值 |
|------|-----|
| **任务ID** | {mission_id} |
| **项目名称** | {project_name} |
| **目标** | {target} |
| **任务类型** | {mission_type} |
| **启动时间** | {datetime.now().strftime('%Y-%m-%d %H:%M')} |
| **当前阶段** | Recon |
| **状态** | 🟢 Active |

## 预算控制
| 分配预算 | 已花费 | 剩余 |
|----------|--------|------|
| $0.00 | $0.00 | $0.00 |

## 任务看板 (Kanban)
| ID | 任务描述 | 负责人 | 状态 | 交付物 | 成本 |
|:---|:---------|:-------|:-----|:-------|:-----|
| T01 | 资产发现与指纹识别 | Recon | ⏳ Pending | recon_results.json | - |

## 发现汇总
| 严重程度 | 数量 |
|:---------|:-----|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 0 |
| 🟢 Low | 0 |
| ⚪ Info | 0 |

## 活动日志
- [{datetime.now().strftime('%H:%M')}] Mission initialized: {mission_id}
"""
        
        with open(self.mission_file, "w", encoding="utf-8") as f:
            f.write(content)
        
        return mission_id
    
    def add_task(self, task_id: str, description: str, agent: str, 
                 status: str = "Pending", deliverable: str = "", 
                 estimated_cost: float = 0.0) -> Dict:
        """Add a new task to the mission"""
        task = {
            "id": task_id,
            "description": description,
            "agent": agent,
            "status": status,
            "deliverable": deliverable,
            "estimated_cost": estimated_cost,
            "actual_cost": 0.0,
            "created_at": datetime.now().isoformat(),
            "completed_at": None
        }
        
        self.mission_data["tasks"].append(task)
        self._update_mission_file()
        
        return task
    
    def update_task_status(self, task_id: str, status: str, 
                          deliverable: str = None, actual_cost: float = None):
        """Update task status and optionally deliverable/cost"""
        for task in self.mission_data["tasks"]:
            if task["id"] == task_id:
                task["status"] = status
                if deliverable:
                    task["deliverable"] = deliverable
                if actual_cost is not None:
                    task["actual_cost"] = actual_cost
                    self.mission_data["budget"]["spent"] += actual_cost
                if status in ["Completed", "Done", "✅ Done"]:
                    task["completed_at"] = datetime.now().isoformat()
                break
        
        self._update_mission_file()
        self._append_log(f"Task {task_id} updated to {status}")
    
    def add_finding(self, finding_id: str, title: str, severity: str,
                   description: str, evidence: Dict[str, Any]) -> Dict:
        """Add a security finding"""
        finding = {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "status": "Open",
            "created_at": datetime.now().isoformat(),
            "validated": False,
            "reachable": False
        }
        
        self.mission_data["findings"].append(finding)
        self._update_mission_file()
        
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "⚪"
        }.get(severity.lower(), "⚪")
        
        self._append_log(f"New finding added: {title} ({severity_emoji} {severity})")
        
        return finding
    
    def update_finding_status(self, finding_id: str, validated: bool = None, 
                             reachable: bool = None, status: str = None):
        """Update finding validation/reachability status"""
        for finding in self.mission_data["findings"]:
            if finding["id"] == finding_id:
                if validated is not None:
                    finding["validated"] = validated
                if reachable is not None:
                    finding["reachable"] = reachable
                if status:
                    finding["status"] = status
                break

        self._update_mission_file()

    # === 多级预算控制 ===

    def set_budget(
        self,
        allocated: float = None,
        max_hours: float = None,
        max_tokens: int = None,
        per_agent_max: int = None,
        per_agent_warn: int = None,
    ):
        """
        设置多级预算参数

        Args:
            allocated: 分配的预算金额 (美元)
            max_hours: 最大 Agent 小时
            max_tokens: 最大 Token 数
            per_agent_max: 每个 Agent 最大 Token
            per_agent_warn: 每个 Agent 警告阈值
        """
        if allocated is not None:
            self.mission_data["budget"]["allocated"] = allocated
        if max_hours is not None:
            self.budget_controller.max_hours = max_hours
        if max_tokens is not None:
            self.budget_controller.max_tokens = max_tokens
        if per_agent_max is not None:
            self.budget_controller.per_agent_max = per_agent_max
        if per_agent_warn is not None:
            self.budget_controller.per_agent_warn = per_agent_warn

        self._update_mission_file()

        log_parts = []
        if allocated is not None:
            log_parts.append(f"${allocated:.2f}")
        if max_hours is not None:
            log_parts.append(f"{max_hours}h")
        if max_tokens is not None:
            log_parts.append(f"{max_tokens} tokens")

        self._append_log(f"Budget configured: {', '.join(log_parts)}")

    def get_budget_status(self) -> Dict[str, Any]:
        """获取完整预算状态"""
        campaign = self.budget_controller.get_campaign_budget()

        return {
            "campaign": campaign,
            "per_agent": {
                agent: self.budget_controller.get_agent_budget(agent)
                for agent in self.budget_controller._agent_budgets
            },
            "warnings": self.budget_controller.check_warnings(),
        }

    def check_budget(self, agent_name: str = None, delta_hours: float = 0, delta_tokens: int = 0) -> tuple[bool, str]:
        """
        检查预算是否足够

        Args:
            agent_name: Agent 名称 (可选，用于 Per-Agent 检查)
            delta_hours: 本次操作预计消耗的小时数
            delta_tokens: 本次操作预计消耗的 Token 数

        Returns:
            (can_proceed, reason)
        """
        # Campaign 级别检查
        ok, reason = self.budget_controller.check_campaign_budget(delta_hours, delta_tokens)
        if not ok:
            return False, reason

        # Per-Agent 级别检查
        if agent_name:
            ok, reason = self.budget_controller.check_agent_budget(agent_name, delta_tokens)
            if not ok:
                return False, reason

        return True, "OK"

    def add_cost(self, cost: float, agent_name: str = None, tokens_used: int = 0, hours_used: float = 0):
        """
        添加成本到预算

        Args:
            cost: 美元成本
            agent_name: Agent 名称 (可选，用于 Per-Agent 追踪)
            tokens_used: Token 消耗 (用于 Per-Agent 预算)
            hours_used: 小时消耗 (用于 Campaign 预算)
        """
        self.mission_data["budget"]["spent"] += cost

        # 更新多级预算
        self.budget_controller.update_campaign(hours_used, tokens_used)

        if agent_name:
            self.budget_controller.update_agent(agent_name, tokens_used)

        self._update_mission_file()

        # 检查警告
        warnings = self.budget_controller.check_warnings(agent_name)
        for warning in warnings:
            self._append_log(f"⚠️ {warning['message']}")

    def should_generate_partial_report(self) -> bool:
        """检查是否应该生成部分报告 (预算耗尽时)"""
        return self.budget_controller.should_generate_partial_report()

    def set_stage(self, stage: str):
        """Update current mission stage"""
        old_stage = self.mission_data["current_stage"]
        self.mission_data["current_stage"] = stage
        self._update_mission_file()
        self._append_log(f"Stage transition: {old_stage} → {stage}")
    
    def complete_mission(self, summary: str = ""):
        """Mark mission as completed"""
        self.mission_data["status"] = "completed"
        self.mission_data["end_time"] = datetime.now().isoformat()
        self._update_mission_file()
        self._append_log(f"Mission completed. {summary}")
    
    def log_advisor_recommendation(self, recommendation: str):
        """Log advisor recommendation"""
        self._append_log(f"💡 Advisor: {recommendation}")
    
    def trigger_reflexion(self, task_id: str, failure_reason: str):
        """Trigger reflexion for failed task"""
        self._append_log(f"🔄 Reflexion triggered for {task_id}: {failure_reason}")
        self.log_advisor_recommendation(f"Analysis of {task_id} failure: {failure_reason}")
    
    def _update_mission_file(self):
        """Update the mission control markdown file"""
        # Calculate statistics
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.mission_data["findings"]:
            sev = finding["severity"].lower()
            if sev in findings_by_severity:
                findings_by_severity[sev] += 1
        
        # Build task table
        task_rows = []
        for task in self.mission_data["tasks"]:
            status_emoji = {
                "pending": "⏳", "in_progress": "🔄", "completed": "✅",
                "done": "✅", "failed": "❌", "blocked": "🚫"
            }.get(task["status"].lower(), "⏳")
            
            cost_str = f"${task['actual_cost']:.2f}" if task['actual_cost'] > 0 else "-"
            task_rows.append(
                f"| {task['id']} | {task['description']} | {task['agent']} | "
                f"{status_emoji} {task['status']} | {task['deliverable']} | {cost_str} |"
            )
        
        tasks_table = "\n".join(task_rows) if task_rows else "| - | No tasks yet | - | - | - | - |"
        
        # Budget
        allocated = self.mission_data["budget"]["allocated"]
        spent = self.mission_data["budget"]["spent"]
        remaining = allocated - spent
        
        status_emoji = "🟢" if self.mission_data["status"] == "active" else "✅"
        
        content = f"""# 🕹️ 任务控制台 (Mission Control)

## 基本信息
| 字段 | 值 |
|------|-----|
| **任务ID** | {self.mission_data.get('mission_id', 'N/A')} |
| **项目名称** | {self.mission_data.get('project_name', 'N/A')} |
| **目标** | {self.mission_data.get('target', 'N/A')} |
| **任务类型** | {self.mission_data.get('mission_type', 'N/A')} |
| **启动时间** | {self.mission_data.get('start_time', 'N/A')} |
| **当前阶段** | {self.mission_data.get('current_stage', 'N/A')} |
| **状态** | {status_emoji} {self.mission_data.get('status', 'unknown').upper()} |

## 预算控制
| 分配预算 | 已花费 | 剩余 |
|----------|--------|------|
| ${allocated:.2f} | ${spent:.2f} | ${remaining:.2f} |

## 任务看板 (Kanban)
| ID | 任务描述 | 负责人 | 状态 | 交付物 | 成本 |
|:---|:---------|:-------|:-----|:-------|:-----|
{tasks_table}

## 发现汇总
| 严重程度 | 数量 |
|:---------|:-----|
| 🔴 Critical | {findings_by_severity['critical']} |
| 🟠 High | {findings_by_severity['high']} |
| 🟡 Medium | {findings_by_severity['medium']} |
| 🟢 Low | {findings_by_severity['low']} |
| ⚪ Info | {findings_by_severity['info']} |
| **总计** | **{sum(findings_by_severity.values())}** |

## 发现详情
"""
        
        # Add findings
        if self.mission_data["findings"]:
            for finding in self.mission_data["findings"]:
                sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", 
                           "low": "🟢", "info": "⚪"}.get(finding['severity'].lower(), "⚪")
                
                validated = "✅" if finding.get('validated') else "⏳"
                reachable = "✅" if finding.get('reachable') else "⏳"
                
                content += f"""
### {finding['id']}: {finding['title']}
- **严重程度**: {sev_emoji} {finding['severity']}
- **状态**: {finding['status']}
- **验证状态**: {validated} Validated | {reachable} Reachable
- **描述**: {finding['description']}
"""
        else:
            content += "\n_No findings recorded yet._\n"
        
        # Add log section
        content += """
## 活动日志
"""
        
        with open(self.mission_file, "r", encoding="utf-8") as f:
            existing_content = f.read()
        
        # Extract existing logs
        log_pattern = r'## 活动日志\n(.*?)(?=\n## |\Z)'
        log_match = re.search(log_pattern, existing_content, re.DOTALL)
        existing_logs = log_match.group(1).strip() if log_match else ""
        
        content += existing_logs
        
        with open(self.mission_file, "w", encoding="utf-8") as f:
            f.write(content)
    
    def _append_log(self, message: str):
        """Append a log entry to the mission file"""
        timestamp = datetime.now().strftime('%H:%M')
        log_entry = f"\n- [{timestamp}] {message}"
        
        with open(self.mission_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
    
    def get_mission_summary(self) -> Dict[str, Any]:
        """Get mission summary statistics"""
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.mission_data["findings"]:
            sev = finding["severity"].lower()
            if sev in findings_by_severity:
                findings_by_severity[sev] += 1
        
        tasks_by_status = {}
        for task in self.mission_data["tasks"]:
            status = task["status"]
            tasks_by_status[status] = tasks_by_status.get(status, 0) + 1
        
        return {
            "mission_id": self.mission_data.get("mission_id"),
            "project_name": self.mission_data.get("project_name"),
            "target": self.mission_data.get("target"),
            "status": self.mission_data.get("status"),
            "current_stage": self.mission_data.get("current_stage"),
            "findings": findings_by_severity,
            "total_findings": sum(findings_by_severity.values()),
            "tasks": tasks_by_status,
            "total_tasks": len(self.mission_data["tasks"]),
            "budget": self.mission_data["budget"]
        }

if __name__ == "__main__":
    # Example usage
    orchestrator = MissionOrchestrator()
    mission_id = orchestrator.initialize_mission("Test Audit", "https://example.com")
    print(f"Mission initialized: {mission_id}")
    
    orchestrator.set_budget(100.0)
    orchestrator.add_task("T01", "Reconnaissance", "Recon Agent", deliverable="assets.json")
    orchestrator.update_task_status("T01", "Completed", "assets.json", 5.0)
    orchestrator.add_finding("F01", "SQL Injection", "high", "SQLi in login form", {"url": "/login"})
    
    summary = orchestrator.get_mission_summary()
    print(f"Summary: {json.dumps(summary, indent=2)}")
